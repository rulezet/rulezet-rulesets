rule TTP_XOR_QUAD_CurrentVersionRun_dfff {
  strings:
    $key_dfff = { 8c 90 [2] a8 9e [2] 83 b2 [2] ad 90 [2] b9 8b [2] b6 91 [2] a8 8c [2] aa 8d [2] b1 8b [2] ad 8c [2] b1 a3 }

  condition:
    any of them
}