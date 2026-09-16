rule TTP_XOR_QUAD_CurrentVersionRun_712f {
  strings:
    $key_712f = { 22 40 [2] 06 4e [2] 2d 62 [2] 03 40 [2] 17 5b [2] 18 41 [2] 06 5c [2] 04 5d [2] 1f 5b [2] 03 5c [2] 1f 73 }

  condition:
    any of them
}