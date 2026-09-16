rule TTP_XOR_QUAD_CurrentVersionRun_ecf8 {
  strings:
    $key_ecf8 = { bf 97 [2] 9b 99 [2] b0 b5 [2] 9e 97 [2] 8a 8c [2] 85 96 [2] 9b 8b [2] 99 8a [2] 82 8c [2] 9e 8b [2] 82 a4 }

  condition:
    any of them
}