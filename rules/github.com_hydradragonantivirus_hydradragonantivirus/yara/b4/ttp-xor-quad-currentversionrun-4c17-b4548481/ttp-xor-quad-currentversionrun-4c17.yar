rule TTP_XOR_QUAD_CurrentVersionRun_4c17 {
  strings:
    $key_4c17 = { 1f 78 [2] 3b 76 [2] 10 5a [2] 3e 78 [2] 2a 63 [2] 25 79 [2] 3b 64 [2] 39 65 [2] 22 63 [2] 3e 64 [2] 22 4b }

  condition:
    any of them
}