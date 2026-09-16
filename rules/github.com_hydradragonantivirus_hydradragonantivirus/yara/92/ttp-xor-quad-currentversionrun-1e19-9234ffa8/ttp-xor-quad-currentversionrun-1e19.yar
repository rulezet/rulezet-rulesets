rule TTP_XOR_QUAD_CurrentVersionRun_1e19 {
  strings:
    $key_1e19 = { 4d 76 [2] 69 78 [2] 42 54 [2] 6c 76 [2] 78 6d [2] 77 77 [2] 69 6a [2] 6b 6b [2] 70 6d [2] 6c 6a [2] 70 45 }

  condition:
    any of them
}