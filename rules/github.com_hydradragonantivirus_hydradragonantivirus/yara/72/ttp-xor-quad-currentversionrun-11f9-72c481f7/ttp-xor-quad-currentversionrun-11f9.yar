rule TTP_XOR_QUAD_CurrentVersionRun_11f9 {
  strings:
    $key_11f9 = { 42 96 [2] 66 98 [2] 4d b4 [2] 63 96 [2] 77 8d [2] 78 97 [2] 66 8a [2] 64 8b [2] 7f 8d [2] 63 8a [2] 7f a5 }

  condition:
    any of them
}