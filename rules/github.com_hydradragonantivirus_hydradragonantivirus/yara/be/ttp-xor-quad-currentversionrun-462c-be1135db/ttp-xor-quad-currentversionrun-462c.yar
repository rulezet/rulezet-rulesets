rule TTP_XOR_QUAD_CurrentVersionRun_462c {
  strings:
    $key_462c = { 15 43 [2] 31 4d [2] 1a 61 [2] 34 43 [2] 20 58 [2] 2f 42 [2] 31 5f [2] 33 5e [2] 28 58 [2] 34 5f [2] 28 70 }

  condition:
    any of them
}