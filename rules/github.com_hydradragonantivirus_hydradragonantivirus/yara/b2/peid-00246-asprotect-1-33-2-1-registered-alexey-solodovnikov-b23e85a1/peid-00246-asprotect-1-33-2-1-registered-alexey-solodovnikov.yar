rule PEiD_00246_ASProtect_1_33___2_1_Registered____Alexey_Solodovnikov_ {
  meta:
    description = "[ASProtect 1.33 - 2.1 Registered -> Alexey Solodovnikov]"
    ep_only     = "true"

  strings:
    $a = { 68 01 ?? ?? ?? E8 01 00 00 00 C3 C3 }

  condition:
    $a
}