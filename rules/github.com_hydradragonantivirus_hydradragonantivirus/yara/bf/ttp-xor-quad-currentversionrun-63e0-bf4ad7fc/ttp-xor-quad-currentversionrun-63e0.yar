rule TTP_XOR_QUAD_CurrentVersionRun_63e0 {
  strings:
    $key_63e0 = { 30 8f [2] 14 81 [2] 3f ad [2] 11 8f [2] 05 94 [2] 0a 8e [2] 14 93 [2] 16 92 [2] 0d 94 [2] 11 93 [2] 0d bc }

  condition:
    any of them
}