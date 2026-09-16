rule TTP_XOR_QUAD_CurrentVersionRun_2ded {
  strings:
    $key_2ded = { 7e 82 [2] 5a 8c [2] 71 a0 [2] 5f 82 [2] 4b 99 [2] 44 83 [2] 5a 9e [2] 58 9f [2] 43 99 [2] 5f 9e [2] 43 b1 }

  condition:
    any of them
}