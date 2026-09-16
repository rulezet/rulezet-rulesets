rule TTP_XOR_QUAD_CurrentVersionRun_1954 {
  strings:
    $key_1954 = { 4a 3b [2] 6e 35 [2] 45 19 [2] 6b 3b [2] 7f 20 [2] 70 3a [2] 6e 27 [2] 6c 26 [2] 77 20 [2] 6b 27 [2] 77 08 }

  condition:
    any of them
}