rule TTP_XOR_QUAD_CurrentVersionRun_2fe5 {
  strings:
    $key_2fe5 = { 7c 8a [2] 58 84 [2] 73 a8 [2] 5d 8a [2] 49 91 [2] 46 8b [2] 58 96 [2] 5a 97 [2] 41 91 [2] 5d 96 [2] 41 b9 }

  condition:
    any of them
}