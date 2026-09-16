rule TTP_XOR_QUAD_CurrentVersionRun_3c04 {
  strings:
    $key_3c04 = { 6f 6b [2] 4b 65 [2] 60 49 [2] 4e 6b [2] 5a 70 [2] 55 6a [2] 4b 77 [2] 49 76 [2] 52 70 [2] 4e 77 [2] 52 58 }

  condition:
    any of them
}