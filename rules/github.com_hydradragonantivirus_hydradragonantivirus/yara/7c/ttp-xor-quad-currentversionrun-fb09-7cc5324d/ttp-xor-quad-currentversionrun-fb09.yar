rule TTP_XOR_QUAD_CurrentVersionRun_fb09 {
  strings:
    $key_fb09 = { a8 66 [2] 8c 68 [2] a7 44 [2] 89 66 [2] 9d 7d [2] 92 67 [2] 8c 7a [2] 8e 7b [2] 95 7d [2] 89 7a [2] 95 55 }

  condition:
    any of them
}