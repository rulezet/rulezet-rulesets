rule TTP_XOR_QUAD_CurrentVersionRun_4937 {
  strings:
    $key_4937 = { 1a 58 [2] 3e 56 [2] 15 7a [2] 3b 58 [2] 2f 43 [2] 20 59 [2] 3e 44 [2] 3c 45 [2] 27 43 [2] 3b 44 [2] 27 6b }

  condition:
    any of them
}