rule TTP_XOR_QUAD_CurrentVersionRun_664c {
  strings:
    $key_664c = { 35 23 [2] 11 2d [2] 3a 01 [2] 14 23 [2] 00 38 [2] 0f 22 [2] 11 3f [2] 13 3e [2] 08 38 [2] 14 3f [2] 08 10 }

  condition:
    any of them
}