rule TTP_XOR_QUAD_CurrentVersionRun_04e5 {
  strings:
    $key_04e5 = { 57 8a [2] 73 84 [2] 58 a8 [2] 76 8a [2] 62 91 [2] 6d 8b [2] 73 96 [2] 71 97 [2] 6a 91 [2] 76 96 [2] 6a b9 }

  condition:
    any of them
}