rule PEiD_01788_Protector_v1_1_11__DDeM____PE_Engine_v0_9__DDeM____CI_v0_9_2__ {
  meta:
    description = "[Protector v1.1.11 (DDeM -> PE Engine v0.9, DDeM -> CI v0.9.2)]"
    ep_only     = "true"

  strings:
    $a = { 53 51 56 E8 00 00 00 00 5B 81 EB 08 10 00 00 8D B3 34 10 00 00 B9 F3 03 00 00 BA 63 17 2A EE 31 16 83 C6 04 }

  condition:
    $a
}