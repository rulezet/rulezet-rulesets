rule TTP_XOR_QUAD_CurrentVersionRun_1945 {
  strings:
    $key_1945 = { 4a 2a [2] 6e 24 [2] 45 08 [2] 6b 2a [2] 7f 31 [2] 70 2b [2] 6e 36 [2] 6c 37 [2] 77 31 [2] 6b 36 [2] 77 19 }

  condition:
    any of them
}