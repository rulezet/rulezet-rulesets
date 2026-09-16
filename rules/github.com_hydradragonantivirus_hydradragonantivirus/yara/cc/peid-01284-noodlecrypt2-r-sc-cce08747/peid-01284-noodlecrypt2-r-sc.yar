rule PEiD_01284_Noodlecrypt2____r_sc_ {
  meta:
    description = "[Noodlecrypt2 -> r!sc]"
    ep_only     = "true"

  strings:
    $a = { EB 01 9A E8 76 00 00 00 }

  condition:
    $a
}