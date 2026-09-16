rule TTP_XOR_QUAD_CurrentVersionRun_fb27 {
  strings:
    $key_fb27 = { a8 48 [2] 8c 46 [2] a7 6a [2] 89 48 [2] 9d 53 [2] 92 49 [2] 8c 54 [2] 8e 55 [2] 95 53 [2] 89 54 [2] 95 7b }

  condition:
    any of them
}