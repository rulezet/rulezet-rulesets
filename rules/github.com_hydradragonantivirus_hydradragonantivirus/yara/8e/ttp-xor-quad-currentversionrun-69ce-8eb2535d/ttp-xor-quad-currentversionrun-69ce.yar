rule TTP_XOR_QUAD_CurrentVersionRun_69ce {
  strings:
    $key_69ce = { 3a a1 [2] 1e af [2] 35 83 [2] 1b a1 [2] 0f ba [2] 00 a0 [2] 1e bd [2] 1c bc [2] 07 ba [2] 1b bd [2] 07 92 }

  condition:
    any of them
}