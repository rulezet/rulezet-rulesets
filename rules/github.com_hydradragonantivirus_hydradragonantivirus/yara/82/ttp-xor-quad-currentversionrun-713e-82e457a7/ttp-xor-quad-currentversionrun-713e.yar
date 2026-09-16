rule TTP_XOR_QUAD_CurrentVersionRun_713e {
  strings:
    $key_713e = { 22 51 [2] 06 5f [2] 2d 73 [2] 03 51 [2] 17 4a [2] 18 50 [2] 06 4d [2] 04 4c [2] 1f 4a [2] 03 4d [2] 1f 62 }

  condition:
    any of them
}