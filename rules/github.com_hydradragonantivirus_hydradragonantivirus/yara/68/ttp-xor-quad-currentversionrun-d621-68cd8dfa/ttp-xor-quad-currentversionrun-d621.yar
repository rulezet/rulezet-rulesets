rule TTP_XOR_QUAD_CurrentVersionRun_d621 {
  strings:
    $key_d621 = { 85 4e [2] a1 40 [2] 8a 6c [2] a4 4e [2] b0 55 [2] bf 4f [2] a1 52 [2] a3 53 [2] b8 55 [2] a4 52 [2] b8 7d }

  condition:
    any of them
}