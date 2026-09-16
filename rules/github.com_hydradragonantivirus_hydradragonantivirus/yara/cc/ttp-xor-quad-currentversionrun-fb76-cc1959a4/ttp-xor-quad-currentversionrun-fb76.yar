rule TTP_XOR_QUAD_CurrentVersionRun_fb76 {
  strings:
    $key_fb76 = { a8 19 [2] 8c 17 [2] a7 3b [2] 89 19 [2] 9d 02 [2] 92 18 [2] 8c 05 [2] 8e 04 [2] 95 02 [2] 89 05 [2] 95 2a }

  condition:
    any of them
}