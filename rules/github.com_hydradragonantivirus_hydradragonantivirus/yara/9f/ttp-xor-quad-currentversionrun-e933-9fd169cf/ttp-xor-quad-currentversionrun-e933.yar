rule TTP_XOR_QUAD_CurrentVersionRun_e933 {
  strings:
    $key_e933 = { ba 5c [2] 9e 52 [2] b5 7e [2] 9b 5c [2] 8f 47 [2] 80 5d [2] 9e 40 [2] 9c 41 [2] 87 47 [2] 9b 40 [2] 87 6f }

  condition:
    any of them
}