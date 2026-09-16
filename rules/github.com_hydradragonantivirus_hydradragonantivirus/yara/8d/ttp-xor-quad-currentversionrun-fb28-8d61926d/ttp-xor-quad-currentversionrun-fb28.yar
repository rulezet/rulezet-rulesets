rule TTP_XOR_QUAD_CurrentVersionRun_fb28 {
  strings:
    $key_fb28 = { a8 47 [2] 8c 49 [2] a7 65 [2] 89 47 [2] 9d 5c [2] 92 46 [2] 8c 5b [2] 8e 5a [2] 95 5c [2] 89 5b [2] 95 74 }

  condition:
    any of them
}