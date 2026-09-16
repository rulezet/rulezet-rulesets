rule _Trojan_Autorun_Trojan_GenericKD_72869045_Virus_Hijack_Gen_Troja_396 {
  meta:
    description = "datamaliciousorder - from files Trojan.Autorun_Trojan.GenericKD.72869045.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8W@aKoUq3b_10_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8W@aKoUq3b_11_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8W@aKoUq3b_13_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.g8W@aiHu4Wp_15_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.g8W@aiHu4Wp_2_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.g8W@aiHu4Wp_3_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.p8W@aCNb4Uo_5_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.p8W@aCNb4Uo_6_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8b4d08c1939546a758d6fe9b1b5284dc628aff3fef3cb798a4e535143a008a56"
    hash2       = "9dd481aae9a5d9bb4492b165f159bb9b6e7d7a9fc94fa24820790c8c1d87ee10"
    hash3       = "70026ec3929b27d3b7979666f6269ba6d6c5691abe9c4eb63fd04989c348f0c1"
    hash4       = "6a3ecd6dd8f8099413faeda6715cf1be7c4fd9388a5e35e2084d7641fc143965"
    hash5       = "6eca375518c871cbafa55bb8b3f323c5138a90fe23a2590be889548e4186ae0c"
    hash6       = "66d0faa4052007cff3969e3b850cf218a17f7cc2a1282c9c956e0402fcfc35e6"
    hash7       = "1300abe8989a2b3b5e1ab0102c4decd1bb1035a73bacbe2b00a064fb74207f7b"
    hash8       = "88161fa41e18f1d57a2848956c024bd4376d03ece61626be61b46da1c9cd0062"
    hash9       = "4a358cd38d34db61937690de1c080533535f35e44b7ccc50d5b07c5bc183a797"

  strings:
    $s1  = "Purging MFT files %d%% complete" fullword ascii
    $s2  = "Pass %d progress: %d%% (%.2f MB/s)" fullword wide
    $s3  = "Target must be formatted as 'driveletter:' (e.g. 'd:') or disk number (e.g. '0')." fullword wide
    $s4  = "Error opening disk %s: " fullword wide
    $s5  = "Error cleaning disk %s: " fullword wide
    $s6  = "Error querying disk %s size: " fullword wide
    $s7  = "   -p         Specifies number of overwrite passes (default is 1)" fullword wide
    $s8  = "   -r         Remove Read-Only attribute" fullword wide
    $s9  = "Cleaning disk %s:" fullword wide
    $s10 = "Error cleaning free space:" fullword wide
    $s11 = "Make sure that the disk has no file system volumes." fullword wide
    $s12 = "Disk %s cleaned." fullword wide
    $s13 = "usage: sdelete [-p passes] [-r] [-s] [-q] <file or directory> [...]" fullword wide
    $s14 = "   -c         Clean free space. Specify an option amount of space" fullword wide
    $s15 = "   -f         Force arguments containing only letters to be treated as a file/directory rather than a disk." fullword wide
    $s16 = "   -s         Recurse subdirectories" fullword wide
    $s17 = "   -z         Zero free space (good for virtual disk optimization)" fullword wide
    $s18 = "A drive letter is required." fullword ascii
    $s19 = "Could not determine disk cluster size: " fullword wide
    $s20 = "Disks must not have any volumes in order to be cleaned." fullword wide

  condition:
    (uint16(0) == 0x5a4d and (8 of them)
    ) or (all of them)
}