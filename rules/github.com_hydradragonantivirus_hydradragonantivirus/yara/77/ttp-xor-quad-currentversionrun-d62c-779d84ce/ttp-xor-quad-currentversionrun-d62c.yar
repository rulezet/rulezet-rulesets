rule TTP_XOR_QUAD_CurrentVersionRun_d62c {
  strings:
    $key_d62c = { 85 43 [2] a1 4d [2] 8a 61 [2] a4 43 [2] b0 58 [2] bf 42 [2] a1 5f [2] a3 5e [2] b8 58 [2] a4 5f [2] b8 70 }

  condition:
    any of them
}