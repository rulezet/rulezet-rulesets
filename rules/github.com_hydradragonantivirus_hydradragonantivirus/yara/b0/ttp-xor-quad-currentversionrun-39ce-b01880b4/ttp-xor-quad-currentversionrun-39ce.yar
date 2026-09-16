rule TTP_XOR_QUAD_CurrentVersionRun_39ce {
  strings:
    $key_39ce = { 6a a1 [2] 4e af [2] 65 83 [2] 4b a1 [2] 5f ba [2] 50 a0 [2] 4e bd [2] 4c bc [2] 57 ba [2] 4b bd [2] 57 92 }

  condition:
    any of them
}