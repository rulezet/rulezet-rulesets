rule TTP_XOR_QUAD_CurrentVersionRun_27ed {
  strings:
    $key_27ed = { 74 82 [2] 50 8c [2] 7b a0 [2] 55 82 [2] 41 99 [2] 4e 83 [2] 50 9e [2] 52 9f [2] 49 99 [2] 55 9e [2] 49 b1 }

  condition:
    any of them
}