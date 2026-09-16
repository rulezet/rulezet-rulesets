rule TTP_XOR_QUAD_CurrentVersionRun_f0e0 {
  strings:
    $key_f0e0 = { a3 8f [2] 87 81 [2] ac ad [2] 82 8f [2] 96 94 [2] 99 8e [2] 87 93 [2] 85 92 [2] 9e 94 [2] 82 93 [2] 9e bc }

  condition:
    any of them
}