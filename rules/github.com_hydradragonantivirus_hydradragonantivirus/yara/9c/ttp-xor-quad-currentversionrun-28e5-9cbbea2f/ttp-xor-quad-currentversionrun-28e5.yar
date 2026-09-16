rule TTP_XOR_QUAD_CurrentVersionRun_28e5 {
  strings:
    $key_28e5 = { 7b 8a [2] 5f 84 [2] 74 a8 [2] 5a 8a [2] 4e 91 [2] 41 8b [2] 5f 96 [2] 5d 97 [2] 46 91 [2] 5a 96 [2] 46 b9 }

  condition:
    any of them
}