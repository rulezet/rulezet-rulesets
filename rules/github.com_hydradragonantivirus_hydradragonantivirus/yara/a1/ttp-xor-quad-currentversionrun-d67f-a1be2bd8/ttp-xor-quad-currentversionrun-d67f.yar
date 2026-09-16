rule TTP_XOR_QUAD_CurrentVersionRun_d67f {
  strings:
    $key_d67f = { 85 10 [2] a1 1e [2] 8a 32 [2] a4 10 [2] b0 0b [2] bf 11 [2] a1 0c [2] a3 0d [2] b8 0b [2] a4 0c [2] b8 23 }

  condition:
    any of them
}