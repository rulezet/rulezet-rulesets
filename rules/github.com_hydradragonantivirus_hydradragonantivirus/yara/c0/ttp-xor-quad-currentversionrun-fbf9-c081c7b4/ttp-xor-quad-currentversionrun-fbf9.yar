rule TTP_XOR_QUAD_CurrentVersionRun_fbf9 {
  strings:
    $key_fbf9 = { a8 96 [2] 8c 98 [2] a7 b4 [2] 89 96 [2] 9d 8d [2] 92 97 [2] 8c 8a [2] 8e 8b [2] 95 8d [2] 89 8a [2] 95 a5 }

  condition:
    any of them
}