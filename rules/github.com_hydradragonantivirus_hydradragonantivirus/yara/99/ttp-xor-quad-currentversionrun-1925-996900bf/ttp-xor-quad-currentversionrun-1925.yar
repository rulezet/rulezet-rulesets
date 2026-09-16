rule TTP_XOR_QUAD_CurrentVersionRun_1925 {
  strings:
    $key_1925 = { 4a 4a [2] 6e 44 [2] 45 68 [2] 6b 4a [2] 7f 51 [2] 70 4b [2] 6e 56 [2] 6c 57 [2] 77 51 [2] 6b 56 [2] 77 79 }

  condition:
    any of them
}