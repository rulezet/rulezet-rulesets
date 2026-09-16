rule TTP_XOR_QUAD_CurrentVersionRun_c3e1 {
  strings:
    $key_c3e1 = { 90 8e [2] b4 80 [2] 9f ac [2] b1 8e [2] a5 95 [2] aa 8f [2] b4 92 [2] b6 93 [2] ad 95 [2] b1 92 [2] ad bd }

  condition:
    any of them
}