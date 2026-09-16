rule TTP_XOR_QUAD_CurrentVersionRun_e9ef {
  strings:
    $key_e9ef = { ba 80 [2] 9e 8e [2] b5 a2 [2] 9b 80 [2] 8f 9b [2] 80 81 [2] 9e 9c [2] 9c 9d [2] 87 9b [2] 9b 9c [2] 87 b3 }

  condition:
    any of them
}