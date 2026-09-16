rule TTP_XOR_QUAD_CurrentVersionRun_7917 {
  strings:
    $key_7917 = { 2a 78 [2] 0e 76 [2] 25 5a [2] 0b 78 [2] 1f 63 [2] 10 79 [2] 0e 64 [2] 0c 65 [2] 17 63 [2] 0b 64 [2] 17 4b }

  condition:
    any of them
}