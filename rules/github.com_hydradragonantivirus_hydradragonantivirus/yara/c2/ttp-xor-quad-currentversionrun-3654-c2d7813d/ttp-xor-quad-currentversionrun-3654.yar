rule TTP_XOR_QUAD_CurrentVersionRun_3654 {
  strings:
    $key_3654 = { 65 3b [2] 41 35 [2] 6a 19 [2] 44 3b [2] 50 20 [2] 5f 3a [2] 41 27 [2] 43 26 [2] 58 20 [2] 44 27 [2] 58 08 }

  condition:
    any of them
}