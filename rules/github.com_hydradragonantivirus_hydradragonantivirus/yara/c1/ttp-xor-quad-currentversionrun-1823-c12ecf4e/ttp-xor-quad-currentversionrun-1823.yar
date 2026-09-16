rule TTP_XOR_QUAD_CurrentVersionRun_1823 {
  strings:
    $key_1823 = { 4b 4c [2] 6f 42 [2] 44 6e [2] 6a 4c [2] 7e 57 [2] 71 4d [2] 6f 50 [2] 6d 51 [2] 76 57 [2] 6a 50 [2] 76 7f }

  condition:
    any of them
}