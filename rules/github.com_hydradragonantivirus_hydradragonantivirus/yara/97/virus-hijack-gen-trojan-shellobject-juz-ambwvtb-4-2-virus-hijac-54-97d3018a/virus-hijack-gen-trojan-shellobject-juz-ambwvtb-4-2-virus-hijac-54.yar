import "pe"
rule _Virus_Hijack_Gen_Trojan_ShellObject_juZ_amBwvTb_4_2_Virus_Hijac_54 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Gen.Trojan.ShellObject.juZ@amBwvTb_4_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.k4Z@aSzGK!f_5_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.l8Z@aKTibuk_8_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.n8Z@amiJMXg_2_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "715694a01d613489d145b78813c9d6b97df12bcbf76828584107d665b14ff89c"
    hash2       = "5381672c2cd5bce09a1cd088c8054430633612b298a32467f45e36097887bfe7"
    hash3       = "6b96afca62b3637a767f130fa06d1475e5e8f575e459b472f265bc199df48ddc"
    hash4       = "87b72062ce8e4ad5e0eadfd3c32db9d7939f34ba5e4e1883bcec85cb8739a8d3"

  strings:
    $x1  = "usage: webmanagement.exe -Sponsor \"appServiceName packageFamilyName requestQueueEventName httpPort httpsPort debugMode traceLev" ascii
    $s2  = "WDP DNSSD service registered: ServiceName=%S, HostName=%S, IP4=%S, IP6=%S, HttpPort=%d, HttpsPort=%S, DeviceFamily=%S, Processor" ascii
    $s3  = "WDP DNSSD service query returned: HostName=%S, IP4=%S, HttpPort=%d, HttpsPort=%d, DeviceFamily=%S, ProcessorArchitecture=%S, Tag" ascii
    $s4  = "WDP DNSSD service registered: ServiceName=%S, HostName=%S, IP4=%S, IP6=%S, HttpPort=%d, HttpsPort=%S, DeviceFamily=%S, Processor" ascii
    $s5  = "WDP DNSSD service query returned: HostName=%S, IP4=%S, HttpPort=%d, HttpsPort=%d, DeviceFamily=%S, ProcessorArchitecture=%S, Tag" ascii
    $s6  = "Failed to open target process: 0x%x" fullword ascii
    $s7  = "Failed to collect live process dump: 0x%x" fullword ascii
    $s8  = "usage: webmanagement.exe -Sponsor \"appServiceName packageFamilyName requestQueueEventName httpPort httpsPort debugMode traceLev" ascii
    $s9  = "Failed to generate live kernel dump name" fullword ascii
    $s10 = "Failed to get crash dump settings" fullword wide
    $s11 = "Failed to get crash dump list" fullword wide
    $s12 = "Too many failed login attempts." fullword ascii
    $s13 = "Access denied - is the server running elevated?" fullword ascii
    $s14 = "Failed to get process information: 0x%x" fullword ascii
    $s15 = "Couldn't get current process token, OpenProcessToken returns hr 0x%X" fullword ascii
    $s16 = "Error: Failed to get process name" fullword wide
    $s17 = "Failed to collect live kernel dump: 0x%x" fullword ascii
    $s18 = "Failed to open interactive process token: 0x%x" fullword ascii
    $s19 = "Failed to create a process stop event %S: 0x%x" fullword ascii
    $s20 = "Failed to create dump file" fullword ascii

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "912919246b7d4e917d5ea76378f11058" and (1 of ($x*) and 4 of them)
    ) or (all of them)
}