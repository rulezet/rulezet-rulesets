rule PEiD_01613_PELOCKnt_2_04_ {
  meta:
    description = "[PELOCKnt 2.04]"
    ep_only     = "true"

  strings:
    $a = { EB 03 CD 20 C7 1E EB 03 CD 20 EA 9C EB 02 EB 01 EB 01 EB 60 }

  condition:
    $a
}