rule PEiD_00215_ASPack_v1_08_01____Alexey_Solodovnikov_ {
  meta:
    description = "[ASPack v1.08.01 -> Alexey Solodovnikov]"
    ep_only     = "true"

  strings:
    $a = { 60 EB ?? 5D EB ?? FF ?? ?? ?? ?? ?? E9 }

  condition:
    $a
}