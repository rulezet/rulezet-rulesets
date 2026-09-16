rule TTP_XOR_QUAD_CurrentVersionRun_e5e8 {
  strings:
    $key_e5e8 = { b6 87 [2] 92 89 [2] b9 a5 [2] 97 87 [2] 83 9c [2] 8c 86 [2] 92 9b [2] 90 9a [2] 8b 9c [2] 97 9b [2] 8b b4 }

  condition:
    any of them
}