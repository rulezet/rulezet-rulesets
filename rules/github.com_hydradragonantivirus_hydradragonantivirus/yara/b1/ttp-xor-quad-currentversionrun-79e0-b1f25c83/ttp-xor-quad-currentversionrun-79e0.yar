rule TTP_XOR_QUAD_CurrentVersionRun_79e0 {
  strings:
    $key_79e0 = { 2a 8f [2] 0e 81 [2] 25 ad [2] 0b 8f [2] 1f 94 [2] 10 8e [2] 0e 93 [2] 0c 92 [2] 17 94 [2] 0b 93 [2] 17 bc }

  condition:
    any of them
}