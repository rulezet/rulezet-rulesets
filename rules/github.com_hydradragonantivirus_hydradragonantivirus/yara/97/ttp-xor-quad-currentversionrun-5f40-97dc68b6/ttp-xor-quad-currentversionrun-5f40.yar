rule TTP_XOR_QUAD_CurrentVersionRun_5f40 {
  strings:
    $key_5f40 = { 0c 2f [2] 28 21 [2] 03 0d [2] 2d 2f [2] 39 34 [2] 36 2e [2] 28 33 [2] 2a 32 [2] 31 34 [2] 2d 33 [2] 31 1c }

  condition:
    any of them
}