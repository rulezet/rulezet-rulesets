rule TTP_XOR_QUAD_CurrentVersionRun_1340 {
  strings:
    $key_1340 = { 40 2f [2] 64 21 [2] 4f 0d [2] 61 2f [2] 75 34 [2] 7a 2e [2] 64 33 [2] 66 32 [2] 7d 34 [2] 61 33 [2] 7d 1c }

  condition:
    any of them
}