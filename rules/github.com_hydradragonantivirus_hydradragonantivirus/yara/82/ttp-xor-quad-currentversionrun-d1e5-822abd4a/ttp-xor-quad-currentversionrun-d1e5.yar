rule TTP_XOR_QUAD_CurrentVersionRun_d1e5 {
  strings:
    $key_d1e5 = { 82 8a [2] a6 84 [2] 8d a8 [2] a3 8a [2] b7 91 [2] b8 8b [2] a6 96 [2] a4 97 [2] bf 91 [2] a3 96 [2] bf b9 }

  condition:
    any of them
}