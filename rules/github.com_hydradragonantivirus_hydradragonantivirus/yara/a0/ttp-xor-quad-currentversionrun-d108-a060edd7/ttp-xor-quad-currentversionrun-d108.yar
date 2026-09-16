rule TTP_XOR_QUAD_CurrentVersionRun_d108 {
  strings:
    $key_d108 = { 82 67 [2] a6 69 [2] 8d 45 [2] a3 67 [2] b7 7c [2] b8 66 [2] a6 7b [2] a4 7a [2] bf 7c [2] a3 7b [2] bf 54 }

  condition:
    any of them
}