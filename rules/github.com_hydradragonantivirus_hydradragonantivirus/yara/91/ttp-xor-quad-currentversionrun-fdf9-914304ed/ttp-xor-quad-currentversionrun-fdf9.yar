rule TTP_XOR_QUAD_CurrentVersionRun_fdf9 {
  strings:
    $key_fdf9 = { ae 96 [2] 8a 98 [2] a1 b4 [2] 8f 96 [2] 9b 8d [2] 94 97 [2] 8a 8a [2] 88 8b [2] 93 8d [2] 8f 8a [2] 93 a5 }

  condition:
    any of them
}