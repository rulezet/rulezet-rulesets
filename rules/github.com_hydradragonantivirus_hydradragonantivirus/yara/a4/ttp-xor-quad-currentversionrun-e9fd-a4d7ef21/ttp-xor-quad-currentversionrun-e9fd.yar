rule TTP_XOR_QUAD_CurrentVersionRun_e9fd {
  strings:
    $key_e9fd = { ba 92 [2] 9e 9c [2] b5 b0 [2] 9b 92 [2] 8f 89 [2] 80 93 [2] 9e 8e [2] 9c 8f [2] 87 89 [2] 9b 8e [2] 87 a1 }

  condition:
    any of them
}