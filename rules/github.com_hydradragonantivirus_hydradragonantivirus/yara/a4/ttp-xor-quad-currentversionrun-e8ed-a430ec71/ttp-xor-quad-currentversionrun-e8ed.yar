rule TTP_XOR_QUAD_CurrentVersionRun_e8ed {
  strings:
    $key_e8ed = { bb 82 [2] 9f 8c [2] b4 a0 [2] 9a 82 [2] 8e 99 [2] 81 83 [2] 9f 9e [2] 9d 9f [2] 86 99 [2] 9a 9e [2] 86 b1 }

  condition:
    any of them
}