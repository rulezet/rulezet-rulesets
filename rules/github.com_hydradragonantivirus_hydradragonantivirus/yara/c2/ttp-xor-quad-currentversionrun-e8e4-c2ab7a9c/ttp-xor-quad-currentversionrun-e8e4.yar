rule TTP_XOR_QUAD_CurrentVersionRun_e8e4 {
  strings:
    $key_e8e4 = { bb 8b [2] 9f 85 [2] b4 a9 [2] 9a 8b [2] 8e 90 [2] 81 8a [2] 9f 97 [2] 9d 96 [2] 86 90 [2] 9a 97 [2] 86 b8 }

  condition:
    any of them
}