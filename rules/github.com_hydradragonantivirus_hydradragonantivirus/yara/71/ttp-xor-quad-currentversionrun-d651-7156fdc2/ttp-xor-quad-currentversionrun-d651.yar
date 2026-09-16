rule TTP_XOR_QUAD_CurrentVersionRun_d651 {
  strings:
    $key_d651 = { 85 3e [2] a1 30 [2] 8a 1c [2] a4 3e [2] b0 25 [2] bf 3f [2] a1 22 [2] a3 23 [2] b8 25 [2] a4 22 [2] b8 0d }

  condition:
    any of them
}