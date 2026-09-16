rule TTP_XOR_QUAD_CurrentVersionRun_e9ed {
  strings:
    $key_e9ed = { ba 82 [2] 9e 8c [2] b5 a0 [2] 9b 82 [2] 8f 99 [2] 80 83 [2] 9e 9e [2] 9c 9f [2] 87 99 [2] 9b 9e [2] 87 b1 }

  condition:
    any of them
}