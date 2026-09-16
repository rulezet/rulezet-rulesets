rule TTP_VirtualAlloc_RWX_loose_1 {
    meta:
        author = "@captainGeech42,@stvemillertime"
        description = "Look for PE files that make plausible calls to VirtualAlloc with RWX permissions (based on arg setup+call insn)"
        date = "2024-01-24"
        version = "1"
        DaysofYARA = "22/100"
    strings:
                                                        $c_32_1 = {6a40 6800300000 [4-20] ff15}
                                                $c_64_1 = {41b940000000 41b800300000 [4-20] ff15}
    condition:
                        uint16be(0) == 0x4d5a and (
            (
                                uint16(uint32(0x3c)+0x18) == 0x10b and                 any of ($c_32_*)
            ) or (
                                uint16(uint32(0x3c)+0x18) == 0x20b and                 any of ($c_64_*)
            )
        )
}