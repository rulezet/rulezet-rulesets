rule TTP_XOR_QUAD_CurrentVersionRun_f8ed {
  strings:
    $key_f8ed = { ab 82 [2] 8f 8c [2] a4 a0 [2] 8a 82 [2] 9e 99 [2] 91 83 [2] 8f 9e [2] 8d 9f [2] 96 99 [2] 8a 9e [2] 96 b1 }

  condition:
    any of them
}