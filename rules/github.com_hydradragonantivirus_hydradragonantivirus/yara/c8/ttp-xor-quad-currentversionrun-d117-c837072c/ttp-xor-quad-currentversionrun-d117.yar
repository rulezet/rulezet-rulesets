rule TTP_XOR_QUAD_CurrentVersionRun_d117 {
  strings:
    $key_d117 = { 82 78 [2] a6 76 [2] 8d 5a [2] a3 78 [2] b7 63 [2] b8 79 [2] a6 64 [2] a4 65 [2] bf 63 [2] a3 64 [2] bf 4b }

  condition:
    any of them
}