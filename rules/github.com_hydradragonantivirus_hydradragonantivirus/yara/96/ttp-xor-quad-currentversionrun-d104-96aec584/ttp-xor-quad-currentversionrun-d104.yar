rule TTP_XOR_QUAD_CurrentVersionRun_d104 {
  strings:
    $key_d104 = { 82 6b [2] a6 65 [2] 8d 49 [2] a3 6b [2] b7 70 [2] b8 6a [2] a6 77 [2] a4 76 [2] bf 70 [2] a3 77 [2] bf 58 }

  condition:
    any of them
}