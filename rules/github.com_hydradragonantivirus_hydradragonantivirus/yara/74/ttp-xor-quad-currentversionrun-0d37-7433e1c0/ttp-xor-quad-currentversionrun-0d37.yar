rule TTP_XOR_QUAD_CurrentVersionRun_0d37 {
  strings:
    $key_0d37 = { 5e 58 [2] 7a 56 [2] 51 7a [2] 7f 58 [2] 6b 43 [2] 64 59 [2] 7a 44 [2] 78 45 [2] 63 43 [2] 7f 44 [2] 63 6b }

  condition:
    any of them
}