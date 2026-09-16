rule TTP_XOR_QUAD_CurrentVersionRun_7af9 {
  strings:
    $key_7af9 = { 29 96 [2] 0d 98 [2] 26 b4 [2] 08 96 [2] 1c 8d [2] 13 97 [2] 0d 8a [2] 0f 8b [2] 14 8d [2] 08 8a [2] 14 a5 }

  condition:
    any of them
}