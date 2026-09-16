rule TTP_XOR_QUAD_CurrentVersionRun_1e09 {
  strings:
    $key_1e09 = { 4d 66 [2] 69 68 [2] 42 44 [2] 6c 66 [2] 78 7d [2] 77 67 [2] 69 7a [2] 6b 7b [2] 70 7d [2] 6c 7a [2] 70 55 }

  condition:
    any of them
}