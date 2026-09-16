rule TTP_XOR_QUAD_CurrentVersionRun_d611 {
  strings:
    $key_d611 = { 85 7e [2] a1 70 [2] 8a 5c [2] a4 7e [2] b0 65 [2] bf 7f [2] a1 62 [2] a3 63 [2] b8 65 [2] a4 62 [2] b8 4d }

  condition:
    any of them
}