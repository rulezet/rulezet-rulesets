rule TTP_XOR_QUAD_CurrentVersionRun_1ded {
  strings:
    $key_1ded = { 4e 82 [2] 6a 8c [2] 41 a0 [2] 6f 82 [2] 7b 99 [2] 74 83 [2] 6a 9e [2] 68 9f [2] 73 99 [2] 6f 9e [2] 73 b1 }

  condition:
    any of them
}