rule TTP_XOR_QUAD_CurrentVersionRun_e9f3 {
  strings:
    $key_e9f3 = { ba 9c [2] 9e 92 [2] b5 be [2] 9b 9c [2] 8f 87 [2] 80 9d [2] 9e 80 [2] 9c 81 [2] 87 87 [2] 9b 80 [2] 87 af }

  condition:
    any of them
}