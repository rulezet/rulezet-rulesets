rule TTP_XOR_QUAD_CurrentVersionRun_fb19 {
  strings:
    $key_fb19 = { a8 76 [2] 8c 78 [2] a7 54 [2] 89 76 [2] 9d 6d [2] 92 77 [2] 8c 6a [2] 8e 6b [2] 95 6d [2] 89 6a [2] 95 45 }

  condition:
    any of them
}