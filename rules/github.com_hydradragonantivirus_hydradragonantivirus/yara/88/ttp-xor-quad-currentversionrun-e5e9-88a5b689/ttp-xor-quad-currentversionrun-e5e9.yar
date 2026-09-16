rule TTP_XOR_QUAD_CurrentVersionRun_e5e9 {
  strings:
    $key_e5e9 = { b6 86 [2] 92 88 [2] b9 a4 [2] 97 86 [2] 83 9d [2] 8c 87 [2] 92 9a [2] 90 9b [2] 8b 9d [2] 97 9a [2] 8b b5 }

  condition:
    any of them
}