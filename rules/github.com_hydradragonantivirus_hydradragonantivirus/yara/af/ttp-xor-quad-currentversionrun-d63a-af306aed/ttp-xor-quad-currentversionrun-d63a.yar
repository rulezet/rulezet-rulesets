rule TTP_XOR_QUAD_CurrentVersionRun_d63a {
  strings:
    $key_d63a = { 85 55 [2] a1 5b [2] 8a 77 [2] a4 55 [2] b0 4e [2] bf 54 [2] a1 49 [2] a3 48 [2] b8 4e [2] a4 49 [2] b8 66 }

  condition:
    any of them
}