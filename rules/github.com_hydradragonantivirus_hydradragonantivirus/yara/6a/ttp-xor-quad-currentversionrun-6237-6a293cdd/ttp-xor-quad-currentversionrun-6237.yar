rule TTP_XOR_QUAD_CurrentVersionRun_6237 {
  strings:
    $key_6237 = { 31 58 [2] 15 56 [2] 3e 7a [2] 10 58 [2] 04 43 [2] 0b 59 [2] 15 44 [2] 17 45 [2] 0c 43 [2] 10 44 [2] 0c 6b }

  condition:
    any of them
}