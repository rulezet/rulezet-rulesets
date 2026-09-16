rule TTP_XOR_QUAD_CurrentVersionRun_0bf8 {
  strings:
    $key_0bf8 = { 58 97 [2] 7c 99 [2] 57 b5 [2] 79 97 [2] 6d 8c [2] 62 96 [2] 7c 8b [2] 7e 8a [2] 65 8c [2] 79 8b [2] 65 a4 }

  condition:
    any of them
}