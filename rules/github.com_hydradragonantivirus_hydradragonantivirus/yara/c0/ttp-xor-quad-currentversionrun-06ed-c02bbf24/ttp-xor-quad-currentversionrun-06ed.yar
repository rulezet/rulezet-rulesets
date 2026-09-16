rule TTP_XOR_QUAD_CurrentVersionRun_06ed {
  strings:
    $key_06ed = { 55 82 [2] 71 8c [2] 5a a0 [2] 74 82 [2] 60 99 [2] 6f 83 [2] 71 9e [2] 73 9f [2] 68 99 [2] 74 9e [2] 68 b1 }

  condition:
    any of them
}