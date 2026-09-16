rule TTP_XOR_QUAD_CurrentVersionRun_fbf8 {
  strings:
    $key_fbf8 = { a8 97 [2] 8c 99 [2] a7 b5 [2] 89 97 [2] 9d 8c [2] 92 96 [2] 8c 8b [2] 8e 8a [2] 95 8c [2] 89 8b [2] 95 a4 }

  condition:
    any of them
}