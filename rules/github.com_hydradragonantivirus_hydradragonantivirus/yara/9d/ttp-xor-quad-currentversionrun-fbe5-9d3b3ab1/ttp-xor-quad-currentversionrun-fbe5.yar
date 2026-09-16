rule TTP_XOR_QUAD_CurrentVersionRun_fbe5 {
  strings:
    $key_fbe5 = { a8 8a [2] 8c 84 [2] a7 a8 [2] 89 8a [2] 9d 91 [2] 92 8b [2] 8c 96 [2] 8e 97 [2] 95 91 [2] 89 96 [2] 95 b9 }

  condition:
    any of them
}