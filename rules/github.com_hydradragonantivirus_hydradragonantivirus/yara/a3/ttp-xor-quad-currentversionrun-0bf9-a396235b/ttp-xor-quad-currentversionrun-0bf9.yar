rule TTP_XOR_QUAD_CurrentVersionRun_0bf9 {
  strings:
    $key_0bf9 = { 58 96 [2] 7c 98 [2] 57 b4 [2] 79 96 [2] 6d 8d [2] 62 97 [2] 7c 8a [2] 7e 8b [2] 65 8d [2] 79 8a [2] 65 a5 }

  condition:
    any of them
}