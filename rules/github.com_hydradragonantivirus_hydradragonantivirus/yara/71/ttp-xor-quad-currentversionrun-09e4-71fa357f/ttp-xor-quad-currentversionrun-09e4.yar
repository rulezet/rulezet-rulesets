rule TTP_XOR_QUAD_CurrentVersionRun_09e4 {
  strings:
    $key_09e4 = { 5a 8b [2] 7e 85 [2] 55 a9 [2] 7b 8b [2] 6f 90 [2] 60 8a [2] 7e 97 [2] 7c 96 [2] 67 90 [2] 7b 97 [2] 67 b8 }

  condition:
    any of them
}