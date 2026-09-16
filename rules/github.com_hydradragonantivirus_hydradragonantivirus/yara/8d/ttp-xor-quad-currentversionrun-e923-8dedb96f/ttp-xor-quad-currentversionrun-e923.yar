rule TTP_XOR_QUAD_CurrentVersionRun_e923 {
  strings:
    $key_e923 = { ba 4c [2] 9e 42 [2] b5 6e [2] 9b 4c [2] 8f 57 [2] 80 4d [2] 9e 50 [2] 9c 51 [2] 87 57 [2] 9b 50 [2] 87 7f }

  condition:
    any of them
}