rule TTP_XOR_QUAD_CurrentVersionRun_e5e4 {
  strings:
    $key_e5e4 = { b6 8b [2] 92 85 [2] b9 a9 [2] 97 8b [2] 83 90 [2] 8c 8a [2] 92 97 [2] 90 96 [2] 8b 90 [2] 97 97 [2] 8b b8 }

  condition:
    any of them
}