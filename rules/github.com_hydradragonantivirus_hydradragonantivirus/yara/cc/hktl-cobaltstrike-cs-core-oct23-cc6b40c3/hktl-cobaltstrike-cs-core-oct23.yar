rule HKTL_CobaltStrike_CS_Core_Oct23 {
    meta:
        description = "Hunts for opcodes used in Cobaltstrike 4.9.1 and earlier"
        version = "0.1"
        author = "@ninjaparanoid"
        reference = "https://github.com/paranoidninja/Cobaltstrike-Detection/blob/main/cs49.yara"
        date = "2023-10-12"
        score = 75
    strings:
        $socks = { 49 8D 55 02 48 8D 4C 24 30 44 0F B7 F8 B8 FF 03 00 00 }
        $core = { 49 B9 01 01 01 01 01 01 01 01 49 0F AF D1 49 83 F8 40 }
    condition:
        1 of them
}