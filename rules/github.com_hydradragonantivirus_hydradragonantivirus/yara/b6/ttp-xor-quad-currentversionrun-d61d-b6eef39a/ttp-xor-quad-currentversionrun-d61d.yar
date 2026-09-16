rule TTP_XOR_QUAD_CurrentVersionRun_d61d {
  strings:
    $key_d61d = { 85 72 [2] a1 7c [2] 8a 50 [2] a4 72 [2] b0 69 [2] bf 73 [2] a1 6e [2] a3 6f [2] b8 69 [2] a4 6e [2] b8 41 }

  condition:
    any of them
}