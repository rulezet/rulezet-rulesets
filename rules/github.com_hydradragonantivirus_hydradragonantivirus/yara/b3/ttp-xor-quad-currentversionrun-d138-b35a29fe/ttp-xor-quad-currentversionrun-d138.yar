rule TTP_XOR_QUAD_CurrentVersionRun_d138 {
  strings:
    $key_d138 = { 82 57 [2] a6 59 [2] 8d 75 [2] a3 57 [2] b7 4c [2] b8 56 [2] a6 4b [2] a4 4a [2] bf 4c [2] a3 4b [2] bf 64 }

  condition:
    any of them
}