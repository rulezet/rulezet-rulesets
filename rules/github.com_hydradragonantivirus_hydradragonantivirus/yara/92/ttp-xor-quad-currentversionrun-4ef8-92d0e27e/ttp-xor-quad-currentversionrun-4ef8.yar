rule TTP_XOR_QUAD_CurrentVersionRun_4ef8 {
  strings:
    $key_4ef8 = { 1d 97 [2] 39 99 [2] 12 b5 [2] 3c 97 [2] 28 8c [2] 27 96 [2] 39 8b [2] 3b 8a [2] 20 8c [2] 3c 8b [2] 20 a4 }

  condition:
    any of them
}