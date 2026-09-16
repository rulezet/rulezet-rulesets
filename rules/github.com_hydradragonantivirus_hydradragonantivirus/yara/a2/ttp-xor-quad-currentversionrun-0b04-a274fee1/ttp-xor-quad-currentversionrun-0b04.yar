rule TTP_XOR_QUAD_CurrentVersionRun_0b04 {
  strings:
    $key_0b04 = { 58 6b [2] 7c 65 [2] 57 49 [2] 79 6b [2] 6d 70 [2] 62 6a [2] 7c 77 [2] 7e 76 [2] 65 70 [2] 79 77 [2] 65 58 }

  condition:
    any of them
}