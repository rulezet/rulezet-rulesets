rule TTP_XOR_QUAD_CurrentVersionRun_d610 {
  strings:
    $key_d610 = { 85 7f [2] a1 71 [2] 8a 5d [2] a4 7f [2] b0 64 [2] bf 7e [2] a1 63 [2] a3 62 [2] b8 64 [2] a4 63 [2] b8 4c }

  condition:
    any of them
}