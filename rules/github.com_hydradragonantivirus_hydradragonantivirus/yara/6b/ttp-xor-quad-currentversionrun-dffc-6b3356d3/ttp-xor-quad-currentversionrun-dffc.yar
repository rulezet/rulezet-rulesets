rule TTP_XOR_QUAD_CurrentVersionRun_dffc {
  strings:
    $key_dffc = { 8c 93 [2] a8 9d [2] 83 b1 [2] ad 93 [2] b9 88 [2] b6 92 [2] a8 8f [2] aa 8e [2] b1 88 [2] ad 8f [2] b1 a0 }

  condition:
    any of them
}