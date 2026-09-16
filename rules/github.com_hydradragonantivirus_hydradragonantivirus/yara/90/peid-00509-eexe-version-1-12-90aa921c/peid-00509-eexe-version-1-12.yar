rule PEiD_00509_EEXE_Version_1_12_ {
  meta:
    description = "[EEXE Version 1.12]"
    ep_only     = "true"

  strings:
    $a = { B4 30 CD 21 3C 03 73 ?? BA 1F 00 0E 1F B4 09 CD 21 B8 FF 4C CD 21 }

  condition:
    $a
}