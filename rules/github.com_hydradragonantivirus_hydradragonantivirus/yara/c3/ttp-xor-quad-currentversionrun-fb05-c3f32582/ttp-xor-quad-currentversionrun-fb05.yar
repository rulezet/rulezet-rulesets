rule TTP_XOR_QUAD_CurrentVersionRun_fb05 {
  strings:
    $key_fb05 = { a8 6a [2] 8c 64 [2] a7 48 [2] 89 6a [2] 9d 71 [2] 92 6b [2] 8c 76 [2] 8e 77 [2] 95 71 [2] 89 76 [2] 95 59 }

  condition:
    any of them
}