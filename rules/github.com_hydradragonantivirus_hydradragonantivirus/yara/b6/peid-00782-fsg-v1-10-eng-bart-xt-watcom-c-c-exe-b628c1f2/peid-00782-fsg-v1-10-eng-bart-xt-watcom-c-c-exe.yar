rule PEiD_00782_FSG_v1_10__Eng_____bart_xt_____Watcom_C_C___EXE__ {
  meta:
    description = "[FSG v1.10 (Eng) -> bart/xt -> (Watcom C/C++ EXE)]"
    ep_only     = "true"

  strings:
    $a = { EB 02 CD 20 03 ?? 8D ?? 80 ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? EB 02 }

  condition:
    $a
}