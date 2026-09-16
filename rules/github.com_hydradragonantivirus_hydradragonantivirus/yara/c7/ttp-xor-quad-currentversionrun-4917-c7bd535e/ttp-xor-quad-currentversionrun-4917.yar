rule TTP_XOR_QUAD_CurrentVersionRun_4917 {
  strings:
    $key_4917 = { 1a 78 [2] 3e 76 [2] 15 5a [2] 3b 78 [2] 2f 63 [2] 20 79 [2] 3e 64 [2] 3c 65 [2] 27 63 [2] 3b 64 [2] 27 4b }

  condition:
    any of them
}