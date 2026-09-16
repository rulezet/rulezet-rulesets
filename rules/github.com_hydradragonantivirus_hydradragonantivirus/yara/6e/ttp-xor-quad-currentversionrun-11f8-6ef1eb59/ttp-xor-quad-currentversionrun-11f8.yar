rule TTP_XOR_QUAD_CurrentVersionRun_11f8 {
  strings:
    $key_11f8 = { 42 97 [2] 66 99 [2] 4d b5 [2] 63 97 [2] 77 8c [2] 78 96 [2] 66 8b [2] 64 8a [2] 7f 8c [2] 63 8b [2] 7f a4 }

  condition:
    any of them
}