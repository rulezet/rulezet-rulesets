rule TTP_XOR_QUAD_CurrentVersionRun_65f9 {
  strings:
    $key_65f9 = { 36 96 [2] 12 98 [2] 39 b4 [2] 17 96 [2] 03 8d [2] 0c 97 [2] 12 8a [2] 10 8b [2] 0b 8d [2] 17 8a [2] 0b a5 }

  condition:
    any of them
}