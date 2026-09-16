rule TTP_XOR_QUAD_CurrentVersionRun_fdf5 {
  strings:
    $key_fdf5 = { ae 9a [2] 8a 94 [2] a1 b8 [2] 8f 9a [2] 9b 81 [2] 94 9b [2] 8a 86 [2] 88 87 [2] 93 81 [2] 8f 86 [2] 93 a9 }

  condition:
    any of them
}