rule TTP_XOR_QUAD_CurrentVersionRun_1948 {
  strings:
    $key_1948 = { 4a 27 [2] 6e 29 [2] 45 05 [2] 6b 27 [2] 7f 3c [2] 70 26 [2] 6e 3b [2] 6c 3a [2] 77 3c [2] 6b 3b [2] 77 14 }

  condition:
    any of them
}