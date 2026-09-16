rule TTP_XOR_QUAD_CurrentVersionRun_3823 {
  strings:
    $key_3823 = { 6b 4c [2] 4f 42 [2] 64 6e [2] 4a 4c [2] 5e 57 [2] 51 4d [2] 4f 50 [2] 4d 51 [2] 56 57 [2] 4a 50 [2] 56 7f }

  condition:
    any of them
}