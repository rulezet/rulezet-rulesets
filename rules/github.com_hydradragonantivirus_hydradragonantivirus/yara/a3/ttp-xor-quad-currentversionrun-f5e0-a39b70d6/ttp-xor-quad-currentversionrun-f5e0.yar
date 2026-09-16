rule TTP_XOR_QUAD_CurrentVersionRun_f5e0 {
  strings:
    $key_f5e0 = { a6 8f [2] 82 81 [2] a9 ad [2] 87 8f [2] 93 94 [2] 9c 8e [2] 82 93 [2] 80 92 [2] 9b 94 [2] 87 93 [2] 9b bc }

  condition:
    any of them
}