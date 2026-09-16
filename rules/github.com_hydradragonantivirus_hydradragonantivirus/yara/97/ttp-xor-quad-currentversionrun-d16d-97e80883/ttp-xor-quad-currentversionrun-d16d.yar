rule TTP_XOR_QUAD_CurrentVersionRun_d16d {
  strings:
    $key_d16d = { 82 02 [2] a6 0c [2] 8d 20 [2] a3 02 [2] b7 19 [2] b8 03 [2] a6 1e [2] a4 1f [2] bf 19 [2] a3 1e [2] bf 31 }

  condition:
    any of them
}