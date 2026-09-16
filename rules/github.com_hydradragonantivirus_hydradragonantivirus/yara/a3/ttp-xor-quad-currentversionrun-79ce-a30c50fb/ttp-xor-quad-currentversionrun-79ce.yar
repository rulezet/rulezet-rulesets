rule TTP_XOR_QUAD_CurrentVersionRun_79ce {
  strings:
    $key_79ce = { 2a a1 [2] 0e af [2] 25 83 [2] 0b a1 [2] 1f ba [2] 10 a0 [2] 0e bd [2] 0c bc [2] 17 ba [2] 0b bd [2] 17 92 }

  condition:
    any of them
}