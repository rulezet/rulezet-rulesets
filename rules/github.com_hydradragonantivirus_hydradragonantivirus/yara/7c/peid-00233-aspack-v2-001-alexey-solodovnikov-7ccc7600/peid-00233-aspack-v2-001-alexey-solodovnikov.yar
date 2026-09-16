rule PEiD_00233_ASPack_v2_001____Alexey_Solodovnikov_ {
  meta:
    description = "[ASPack v2.001 -> Alexey Solodovnikov]"
    ep_only     = "true"

  strings:
    $a = { 60 E8 72 05 00 00 EB 4C }

  condition:
    $a
}