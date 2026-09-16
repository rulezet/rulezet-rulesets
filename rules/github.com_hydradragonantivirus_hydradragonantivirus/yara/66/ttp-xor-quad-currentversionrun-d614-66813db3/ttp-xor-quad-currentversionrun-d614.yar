rule TTP_XOR_QUAD_CurrentVersionRun_d614 {
  strings:
    $key_d614 = { 85 7b [2] a1 75 [2] 8a 59 [2] a4 7b [2] b0 60 [2] bf 7a [2] a1 67 [2] a3 66 [2] b8 60 [2] a4 67 [2] b8 48 }

  condition:
    any of them
}