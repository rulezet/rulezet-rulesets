rule TTP_XOR_QUAD_CurrentVersionRun_09ce {
  strings:
    $key_09ce = { 5a a1 [2] 7e af [2] 55 83 [2] 7b a1 [2] 6f ba [2] 60 a0 [2] 7e bd [2] 7c bc [2] 67 ba [2] 7b bd [2] 67 92 }

  condition:
    any of them
}