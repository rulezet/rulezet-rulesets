rule TTP_XOR_QUAD_CurrentVersionRun_562c {
  strings:
    $key_562c = { 05 43 [2] 21 4d [2] 0a 61 [2] 24 43 [2] 30 58 [2] 3f 42 [2] 21 5f [2] 23 5e [2] 38 58 [2] 24 5f [2] 38 70 }

  condition:
    any of them
}