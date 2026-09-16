rule TTP_XOR_QUAD_CurrentVersionRun_fb34 {
  strings:
    $key_fb34 = { a8 5b [2] 8c 55 [2] a7 79 [2] 89 5b [2] 9d 40 [2] 92 5a [2] 8c 47 [2] 8e 46 [2] 95 40 [2] 89 47 [2] 95 68 }

  condition:
    any of them
}