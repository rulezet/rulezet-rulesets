rule TTP_XOR_QUAD_CurrentVersionRun_d284 {
  strings:
    $key_d284 = { 81 eb [2] a5 e5 [2] 8e c9 [2] a0 eb [2] b4 f0 [2] bb ea [2] a5 f7 [2] a7 f6 [2] bc f0 [2] a0 f7 [2] bc d8 }

  condition:
    any of them
}