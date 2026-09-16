rule TTP_XOR_QUAD_CurrentVersionRun_0ff8 {
  strings:
    $key_0ff8 = { 5c 97 [2] 78 99 [2] 53 b5 [2] 7d 97 [2] 69 8c [2] 66 96 [2] 78 8b [2] 7a 8a [2] 61 8c [2] 7d 8b [2] 61 a4 }

  condition:
    any of them
}