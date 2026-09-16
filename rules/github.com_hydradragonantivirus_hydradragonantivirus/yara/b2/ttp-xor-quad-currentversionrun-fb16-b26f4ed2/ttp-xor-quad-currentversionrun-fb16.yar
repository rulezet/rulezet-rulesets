rule TTP_XOR_QUAD_CurrentVersionRun_fb16 {
  strings:
    $key_fb16 = { a8 79 [2] 8c 77 [2] a7 5b [2] 89 79 [2] 9d 62 [2] 92 78 [2] 8c 65 [2] 8e 64 [2] 95 62 [2] 89 65 [2] 95 4a }

  condition:
    any of them
}