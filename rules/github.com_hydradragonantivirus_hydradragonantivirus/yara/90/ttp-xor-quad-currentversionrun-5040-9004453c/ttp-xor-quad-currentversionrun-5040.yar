rule TTP_XOR_QUAD_CurrentVersionRun_5040 {
  strings:
    $key_5040 = { 03 2f [2] 27 21 [2] 0c 0d [2] 22 2f [2] 36 34 [2] 39 2e [2] 27 33 [2] 25 32 [2] 3e 34 [2] 22 33 [2] 3e 1c }

  condition:
    any of them
}