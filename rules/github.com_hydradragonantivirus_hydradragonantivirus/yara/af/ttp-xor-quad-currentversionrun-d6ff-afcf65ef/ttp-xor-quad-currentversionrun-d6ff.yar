rule TTP_XOR_QUAD_CurrentVersionRun_d6ff {
  strings:
    $key_d6ff = { 85 90 [2] a1 9e [2] 8a b2 [2] a4 90 [2] b0 8b [2] bf 91 [2] a1 8c [2] a3 8d [2] b8 8b [2] a4 8c [2] b8 a3 }

  condition:
    any of them
}