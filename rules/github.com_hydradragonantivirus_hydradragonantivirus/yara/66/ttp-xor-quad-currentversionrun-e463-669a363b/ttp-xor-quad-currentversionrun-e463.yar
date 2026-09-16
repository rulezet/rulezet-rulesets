rule TTP_XOR_QUAD_CurrentVersionRun_e463 {
  strings:
    $key_e463 = { b7 0c [2] 93 02 [2] b8 2e [2] 96 0c [2] 82 17 [2] 8d 0d [2] 93 10 [2] 91 11 [2] 8a 17 [2] 96 10 [2] 8a 3f }

  condition:
    any of them
}