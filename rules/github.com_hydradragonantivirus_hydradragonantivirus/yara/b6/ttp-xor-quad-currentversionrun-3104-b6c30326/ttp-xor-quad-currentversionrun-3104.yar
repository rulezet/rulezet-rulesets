rule TTP_XOR_QUAD_CurrentVersionRun_3104 {
  strings:
    $key_3104 = { 62 6b [2] 46 65 [2] 6d 49 [2] 43 6b [2] 57 70 [2] 58 6a [2] 46 77 [2] 44 76 [2] 5f 70 [2] 43 77 [2] 5f 58 }

  condition:
    any of them
}