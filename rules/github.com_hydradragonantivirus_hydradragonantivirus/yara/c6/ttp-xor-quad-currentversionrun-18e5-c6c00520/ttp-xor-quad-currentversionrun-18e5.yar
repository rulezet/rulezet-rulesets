rule TTP_XOR_QUAD_CurrentVersionRun_18e5 {
  strings:
    $key_18e5 = { 4b 8a [2] 6f 84 [2] 44 a8 [2] 6a 8a [2] 7e 91 [2] 71 8b [2] 6f 96 [2] 6d 97 [2] 76 91 [2] 6a 96 [2] 76 b9 }

  condition:
    any of them
}