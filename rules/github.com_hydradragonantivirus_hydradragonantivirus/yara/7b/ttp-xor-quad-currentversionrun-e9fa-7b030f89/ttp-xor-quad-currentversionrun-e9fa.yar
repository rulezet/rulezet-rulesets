rule TTP_XOR_QUAD_CurrentVersionRun_e9fa {
  strings:
    $key_e9fa = { ba 95 [2] 9e 9b [2] b5 b7 [2] 9b 95 [2] 8f 8e [2] 80 94 [2] 9e 89 [2] 9c 88 [2] 87 8e [2] 9b 89 [2] 87 a6 }

  condition:
    any of them
}