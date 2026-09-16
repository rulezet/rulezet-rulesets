rule TTP_XOR_QUAD_CurrentVersionRun_6ff8 {
  strings:
    $key_6ff8 = { 3c 97 [2] 18 99 [2] 33 b5 [2] 1d 97 [2] 09 8c [2] 06 96 [2] 18 8b [2] 1a 8a [2] 01 8c [2] 1d 8b [2] 01 a4 }

  condition:
    any of them
}