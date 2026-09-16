rule TTP_XOR_QUAD_CurrentVersionRun_1dfd {
  strings:
    $key_1dfd = { 4e 92 [2] 6a 9c [2] 41 b0 [2] 6f 92 [2] 7b 89 [2] 74 93 [2] 6a 8e [2] 68 8f [2] 73 89 [2] 6f 8e [2] 73 a1 }

  condition:
    any of them
}