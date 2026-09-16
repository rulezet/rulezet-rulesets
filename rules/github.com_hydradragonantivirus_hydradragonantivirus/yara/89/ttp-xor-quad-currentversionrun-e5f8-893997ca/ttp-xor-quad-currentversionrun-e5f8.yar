rule TTP_XOR_QUAD_CurrentVersionRun_e5f8 {
  strings:
    $key_e5f8 = { b6 97 [2] 92 99 [2] b9 b5 [2] 97 97 [2] 83 8c [2] 8c 96 [2] 92 8b [2] 90 8a [2] 8b 8c [2] 97 8b [2] 8b a4 }

  condition:
    any of them
}