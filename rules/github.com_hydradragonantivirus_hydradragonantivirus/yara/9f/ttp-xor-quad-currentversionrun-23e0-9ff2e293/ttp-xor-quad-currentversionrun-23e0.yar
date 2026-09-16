rule TTP_XOR_QUAD_CurrentVersionRun_23e0 {
  strings:
    $key_23e0 = { 70 8f [2] 54 81 [2] 7f ad [2] 51 8f [2] 45 94 [2] 4a 8e [2] 54 93 [2] 56 92 [2] 4d 94 [2] 51 93 [2] 4d bc }

  condition:
    any of them
}