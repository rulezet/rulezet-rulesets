rule TTP_XOR_QUAD_CurrentVersionRun_7e04 {
  strings:
    $key_7e04 = { 2d 6b [2] 09 65 [2] 22 49 [2] 0c 6b [2] 18 70 [2] 17 6a [2] 09 77 [2] 0b 76 [2] 10 70 [2] 0c 77 [2] 10 58 }

  condition:
    any of them
}