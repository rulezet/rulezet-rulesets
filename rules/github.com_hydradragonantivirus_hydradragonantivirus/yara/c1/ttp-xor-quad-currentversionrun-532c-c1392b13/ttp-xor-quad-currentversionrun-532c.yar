rule TTP_XOR_QUAD_CurrentVersionRun_532c {
  strings:
    $key_532c = { 00 43 [2] 24 4d [2] 0f 61 [2] 21 43 [2] 35 58 [2] 3a 42 [2] 24 5f [2] 26 5e [2] 3d 58 [2] 21 5f [2] 3d 70 }

  condition:
    any of them
}