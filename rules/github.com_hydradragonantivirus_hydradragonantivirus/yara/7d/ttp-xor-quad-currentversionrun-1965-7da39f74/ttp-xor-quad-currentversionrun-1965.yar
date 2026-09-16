rule TTP_XOR_QUAD_CurrentVersionRun_1965 {
  strings:
    $key_1965 = { 4a 0a [2] 6e 04 [2] 45 28 [2] 6b 0a [2] 7f 11 [2] 70 0b [2] 6e 16 [2] 6c 17 [2] 77 11 [2] 6b 16 [2] 77 39 }

  condition:
    any of them
}