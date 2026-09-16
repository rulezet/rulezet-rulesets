rule TTP_XOR_QUAD_CurrentVersionRun_0a37 {
  strings:
    $key_0a37 = { 59 58 [2] 7d 56 [2] 56 7a [2] 78 58 [2] 6c 43 [2] 63 59 [2] 7d 44 [2] 7f 45 [2] 64 43 [2] 78 44 [2] 64 6b }

  condition:
    any of them
}