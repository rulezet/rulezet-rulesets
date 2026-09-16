rule PEiD_00259_ASProtect_v1_2____Alexey_Solodovnikov__h1__ {
  meta:
    description = "[ASProtect v1.2 -> Alexey Solodovnikov (h1)]"
    ep_only     = "false"

  strings:
    $a = { 90 60 E8 1B 00 00 00 E9 FC 8D B5 0F 06 00 00 8B FE B9 97 00 00 00 AD 35 78 56 34 12 AB 49 75 F6 EB 04 5D 45 55 C3 E9 ?? ?? ?? 00 }

  condition:
    $a
}