rule TTP_XOR_QUAD_CurrentVersionRun_e5f9 {
  strings:
    $key_e5f9 = { b6 96 [2] 92 98 [2] b9 b4 [2] 97 96 [2] 83 8d [2] 8c 97 [2] 92 8a [2] 90 8b [2] 8b 8d [2] 97 8a [2] 8b a5 }

  condition:
    any of them
}