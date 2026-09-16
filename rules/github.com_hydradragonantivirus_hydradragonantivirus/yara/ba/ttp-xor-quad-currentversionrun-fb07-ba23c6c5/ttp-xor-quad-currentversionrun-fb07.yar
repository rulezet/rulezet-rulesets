rule TTP_XOR_QUAD_CurrentVersionRun_fb07 {
  strings:
    $key_fb07 = { a8 68 [2] 8c 66 [2] a7 4a [2] 89 68 [2] 9d 73 [2] 92 69 [2] 8c 74 [2] 8e 75 [2] 95 73 [2] 89 74 [2] 95 5b }

  condition:
    any of them
}