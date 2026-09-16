rule TTP_XOR_QUAD_CurrentVersionRun_1dfc {
  strings:
    $key_1dfc = { 4e 93 [2] 6a 9d [2] 41 b1 [2] 6f 93 [2] 7b 88 [2] 74 92 [2] 6a 8f [2] 68 8e [2] 73 88 [2] 6f 8f [2] 73 a0 }

  condition:
    any of them
}