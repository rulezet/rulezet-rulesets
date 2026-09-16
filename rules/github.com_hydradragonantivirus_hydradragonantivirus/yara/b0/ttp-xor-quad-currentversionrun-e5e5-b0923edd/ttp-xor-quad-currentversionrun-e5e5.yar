rule TTP_XOR_QUAD_CurrentVersionRun_e5e5 {
  strings:
    $key_e5e5 = { b6 8a [2] 92 84 [2] b9 a8 [2] 97 8a [2] 83 91 [2] 8c 8b [2] 92 96 [2] 90 97 [2] 8b 91 [2] 97 96 [2] 8b b9 }

  condition:
    any of them
}