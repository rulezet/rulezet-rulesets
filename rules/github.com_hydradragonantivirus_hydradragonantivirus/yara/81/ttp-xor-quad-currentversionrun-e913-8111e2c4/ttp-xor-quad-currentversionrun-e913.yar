rule TTP_XOR_QUAD_CurrentVersionRun_e913 {
  strings:
    $key_e913 = { ba 7c [2] 9e 72 [2] b5 5e [2] 9b 7c [2] 8f 67 [2] 80 7d [2] 9e 60 [2] 9c 61 [2] 87 67 [2] 9b 60 [2] 87 4f }

  condition:
    any of them
}