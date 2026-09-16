rule TTP_XOR_QUAD_CurrentVersionRun_d139 {
  strings:
    $key_d139 = { 82 56 [2] a6 58 [2] 8d 74 [2] a3 56 [2] b7 4d [2] b8 57 [2] a6 4a [2] a4 4b [2] bf 4d [2] a3 4a [2] bf 65 }

  condition:
    any of them
}