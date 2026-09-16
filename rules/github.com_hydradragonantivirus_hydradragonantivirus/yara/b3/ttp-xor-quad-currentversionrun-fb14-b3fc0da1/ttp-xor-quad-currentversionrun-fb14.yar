rule TTP_XOR_QUAD_CurrentVersionRun_fb14 {
  strings:
    $key_fb14 = { a8 7b [2] 8c 75 [2] a7 59 [2] 89 7b [2] 9d 60 [2] 92 7a [2] 8c 67 [2] 8e 66 [2] 95 60 [2] 89 67 [2] 95 48 }

  condition:
    any of them
}