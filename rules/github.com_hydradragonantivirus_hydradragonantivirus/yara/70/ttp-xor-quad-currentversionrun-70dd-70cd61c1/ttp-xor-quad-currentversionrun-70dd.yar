rule TTP_XOR_QUAD_CurrentVersionRun_70dd {
  strings:
    $key_70dd = { 23 b2 [2] 07 bc [2] 2c 90 [2] 02 b2 [2] 16 a9 [2] 19 b3 [2] 07 ae [2] 05 af [2] 1e a9 [2] 02 ae [2] 1e 81 }

  condition:
    any of them
}