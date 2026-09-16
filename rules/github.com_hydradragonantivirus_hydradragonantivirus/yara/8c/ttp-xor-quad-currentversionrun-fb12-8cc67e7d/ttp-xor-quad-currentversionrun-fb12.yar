rule TTP_XOR_QUAD_CurrentVersionRun_fb12 {
  strings:
    $key_fb12 = { a8 7d [2] 8c 73 [2] a7 5f [2] 89 7d [2] 9d 66 [2] 92 7c [2] 8c 61 [2] 8e 60 [2] 95 66 [2] 89 61 [2] 95 4e }

  condition:
    any of them
}