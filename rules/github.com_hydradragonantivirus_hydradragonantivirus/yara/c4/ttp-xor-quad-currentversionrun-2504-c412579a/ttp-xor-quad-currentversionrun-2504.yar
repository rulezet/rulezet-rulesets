rule TTP_XOR_QUAD_CurrentVersionRun_2504 {
  strings:
    $key_2504 = { 76 6b [2] 52 65 [2] 79 49 [2] 57 6b [2] 43 70 [2] 4c 6a [2] 52 77 [2] 50 76 [2] 4b 70 [2] 57 77 [2] 4b 58 }

  condition:
    any of them
}