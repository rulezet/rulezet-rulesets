rule TTP_XOR_QUAD_CurrentVersionRun_fb38 {
  strings:
    $key_fb38 = { a8 57 [2] 8c 59 [2] a7 75 [2] 89 57 [2] 9d 4c [2] 92 56 [2] 8c 4b [2] 8e 4a [2] 95 4c [2] 89 4b [2] 95 64 }

  condition:
    any of them
}