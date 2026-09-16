rule TTP_XOR_QUAD_CurrentVersionRun_e9ec {
  strings:
    $key_e9ec = { ba 83 [2] 9e 8d [2] b5 a1 [2] 9b 83 [2] 8f 98 [2] 80 82 [2] 9e 9f [2] 9c 9e [2] 87 98 [2] 9b 9f [2] 87 b0 }

  condition:
    any of them
}