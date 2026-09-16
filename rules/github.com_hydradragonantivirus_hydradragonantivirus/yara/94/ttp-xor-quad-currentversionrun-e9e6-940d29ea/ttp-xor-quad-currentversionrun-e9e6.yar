rule TTP_XOR_QUAD_CurrentVersionRun_e9e6 {
  strings:
    $key_e9e6 = { ba 89 [2] 9e 87 [2] b5 ab [2] 9b 89 [2] 8f 92 [2] 80 88 [2] 9e 95 [2] 9c 94 [2] 87 92 [2] 9b 95 [2] 87 ba }

  condition:
    any of them
}