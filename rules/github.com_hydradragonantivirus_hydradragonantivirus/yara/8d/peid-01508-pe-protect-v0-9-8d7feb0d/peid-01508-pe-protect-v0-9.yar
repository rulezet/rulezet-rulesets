rule PEiD_01508_PE_Protect_v0_9_ {
  meta:
    description = "[PE Protect v0.9]"
    ep_only     = "true"

  strings:
    $a = { 52 51 55 57 64 67 A1 30 00 85 C0 78 0D E8 ?? ?? ?? ?? 58 83 C0 07 C6 ?? C3 }

  condition:
    $a
}