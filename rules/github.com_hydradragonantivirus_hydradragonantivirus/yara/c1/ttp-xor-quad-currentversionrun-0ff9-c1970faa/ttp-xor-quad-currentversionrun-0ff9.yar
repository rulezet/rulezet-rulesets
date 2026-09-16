rule TTP_XOR_QUAD_CurrentVersionRun_0ff9 {
  strings:
    $key_0ff9 = { 5c 96 [2] 78 98 [2] 53 b4 [2] 7d 96 [2] 69 8d [2] 66 97 [2] 78 8a [2] 7a 8b [2] 61 8d [2] 7d 8a [2] 61 a5 }

  condition:
    any of them
}