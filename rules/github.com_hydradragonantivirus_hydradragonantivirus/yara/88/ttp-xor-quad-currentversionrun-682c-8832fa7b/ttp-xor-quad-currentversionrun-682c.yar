rule TTP_XOR_QUAD_CurrentVersionRun_682c {
  strings:
    $key_682c = { 3b 43 [2] 1f 4d [2] 34 61 [2] 1a 43 [2] 0e 58 [2] 01 42 [2] 1f 5f [2] 1d 5e [2] 06 58 [2] 1a 5f [2] 06 70 }

  condition:
    any of them
}