rule TTP_XOR_QUAD_CurrentVersionRun_50ce {
  strings:
    $key_50ce = { 03 a1 [2] 27 af [2] 0c 83 [2] 22 a1 [2] 36 ba [2] 39 a0 [2] 27 bd [2] 25 bc [2] 3e ba [2] 22 bd [2] 3e 92 }

  condition:
    any of them
}