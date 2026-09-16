rule TTP_XOR_QUAD_CurrentVersionRun_d103 {
  strings:
    $key_d103 = { 82 6c [2] a6 62 [2] 8d 4e [2] a3 6c [2] b7 77 [2] b8 6d [2] a6 70 [2] a4 71 [2] bf 77 [2] a3 70 [2] bf 5f }

  condition:
    any of them
}