rule TTP_XOR_QUAD_CurrentVersionRun_1e18 {
  strings:
    $key_1e18 = { 4d 77 [2] 69 79 [2] 42 55 [2] 6c 77 [2] 78 6c [2] 77 76 [2] 69 6b [2] 6b 6a [2] 70 6c [2] 6c 6b [2] 70 44 }

  condition:
    any of them
}