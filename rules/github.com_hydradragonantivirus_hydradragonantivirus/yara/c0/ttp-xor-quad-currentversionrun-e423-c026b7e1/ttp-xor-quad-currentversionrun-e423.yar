rule TTP_XOR_QUAD_CurrentVersionRun_e423 {
  strings:
    $key_e423 = { b7 4c [2] 93 42 [2] b8 6e [2] 96 4c [2] 82 57 [2] 8d 4d [2] 93 50 [2] 91 51 [2] 8a 57 [2] 96 50 [2] 8a 7f }

  condition:
    any of them
}