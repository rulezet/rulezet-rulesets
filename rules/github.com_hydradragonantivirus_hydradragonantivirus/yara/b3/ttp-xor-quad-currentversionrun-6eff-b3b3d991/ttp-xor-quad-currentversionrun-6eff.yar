rule TTP_XOR_QUAD_CurrentVersionRun_6eff {
  strings:
    $key_6eff = { 3d 90 [2] 19 9e [2] 32 b2 [2] 1c 90 [2] 08 8b [2] 07 91 [2] 19 8c [2] 1b 8d [2] 00 8b [2] 1c 8c [2] 00 a3 }

  condition:
    any of them
}