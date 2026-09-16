rule TTP_XOR_QUAD_CurrentVersionRun_4f40 {
  strings:
    $key_4f40 = { 1c 2f [2] 38 21 [2] 13 0d [2] 3d 2f [2] 29 34 [2] 26 2e [2] 38 33 [2] 3a 32 [2] 21 34 [2] 3d 33 [2] 21 1c }

  condition:
    any of them
}