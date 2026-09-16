rule TTP_XOR_QUAD_CurrentVersionRun_59ce {
  strings:
    $key_59ce = { 0a a1 [2] 2e af [2] 05 83 [2] 2b a1 [2] 3f ba [2] 30 a0 [2] 2e bd [2] 2c bc [2] 37 ba [2] 2b bd [2] 37 92 }

  condition:
    any of them
}