rule _Virus_Hijack_Gen_Trojan_ShellObject_dyX_ai9jxwp_1_1_Virus_Hijac_178 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Gen.Trojan.ShellObject.dyX@ai9jxwp_1_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_104_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_105_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_106_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8W@aKoUq3b_10_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8W@aKoUq3b_11_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8W@aKoUq3b_12_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8W@aKoUq3b_13_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8W@aKoUq3b_1_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.g8W@aiHu4Wp_15_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.g8W@aiHu4Wp_2_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.g8W@aiHu4Wp_3_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.p8W@aCNb4Uo_5_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.p8W@aCNb4Uo_6_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9a98a2728de2eea7db2532bbf8f79c6ec1dc6a120fe07103807b03434acedd84"
    hash2       = "1402d55ebe79764aa6b500d90065bfe6cac3be6e4b121d503aade48ba3beab58"
    hash3       = "b855bce10c0efd4998e88e95f6bfa4a2f6088c7c5b1befadcff2bb2045f159c7"
    hash4       = "7c9e89c6d6226a5bbb0a4027211b230c847f293a3162d91841125bf0ad032ad9"
    hash5       = "9dd481aae9a5d9bb4492b165f159bb9b6e7d7a9fc94fa24820790c8c1d87ee10"
    hash6       = "70026ec3929b27d3b7979666f6269ba6d6c5691abe9c4eb63fd04989c348f0c1"
    hash7       = "00803b2a9624ab755ca403c3abbf03d7dc3ac396a7c3fbcfb7471d7281cdf9d0"
    hash8       = "6a3ecd6dd8f8099413faeda6715cf1be7c4fd9388a5e35e2084d7641fc143965"
    hash9       = "2b6862758d7e1fa0b613e8ef792cc1c36a85e6c0806094fb9cbe5c36045e1dbf"
    hash10      = "6eca375518c871cbafa55bb8b3f323c5138a90fe23a2590be889548e4186ae0c"
    hash11      = "66d0faa4052007cff3969e3b850cf218a17f7cc2a1282c9c956e0402fcfc35e6"
    hash12      = "1300abe8989a2b3b5e1ab0102c4decd1bb1035a73bacbe2b00a064fb74207f7b"
    hash13      = "88161fa41e18f1d57a2848956c024bd4376d03ece61626be61b46da1c9cd0062"
    hash14      = "4a358cd38d34db61937690de1c080533535f35e44b7ccc50d5b07c5bc183a797"

  strings:
    $x1  = "The following example demonstrates this usage. In the first rule group, a process create event will generate when timeout.exe is" wide
    $s2  = "You can use both include and exclude rules for the same tag, where exclude rules override include rules. Within a rule, filter c" wide
    $s3  = "              For example: lsass.exe will match c:\\windows\\system32\\lsass.exe." fullword wide
    $s4  = "    <!-- or 80, and process isn't InternetExplorer -->" fullword wide
    $s5  = " - Config hash:" fullword wide
    $s6  = "          <Image condition=\"end with\">cmd.exe</Image>" fullword wide
    $s7  = "Configuration entries are directly under the Sysmon tag and filters are under the EventFiltering tag. Configuration entries are " wide
    $s8  = "You can use a different condition by specifying it as an attribute. This excludes network activity from processes with iexplore." wide
    $s9  = "Too many entries to monitor for process access. Maximum is %d." fullword wide
    $s10 = " - Config file:" fullword wide
    $s11 = "  CopyOnDeleteProcesses  Strings  Process name(s) for which file deletes will" fullword wide
    $s12 = "       Specify 'all' to dump all schema versions (default is latest)." fullword wide
    $s13 = "On Vista and higher, events are stored in \"Applications and Services Logs/Microsoft/Windows/Sysmon/Operational\". On older syst" wide
    $s14 = "Event filtering allows you to filter generated events. In many cases events can be noisy and gathering everything is not possibl" wide
    $s15 = "Configuration usage (current schema is version: %.2f):" fullword wide
    $s16 = "Invalid input for process access" fullword wide
    $s17 = "Invalid final input for process access" fullword wide
    $s18 = " - Last error: " fullword wide
    $s19 = "Process accessed" fullword wide
    $s20 = " - %-34s onmatch: %s   combine rules using '%s'" fullword wide

  condition:
    (uint16(0) == 0x5a4d and (1 of ($x*) and 4 of them)
    ) or (all of them)
}