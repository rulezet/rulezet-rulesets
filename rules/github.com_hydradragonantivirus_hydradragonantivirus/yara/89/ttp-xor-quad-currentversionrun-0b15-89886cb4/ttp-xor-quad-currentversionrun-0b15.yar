rule TTP_XOR_QUAD_CurrentVersionRun_0b15 {
  strings:
    $key_0b15 = { 58 7a [2] 7c 74 [2] 57 58 [2] 79 7a [2] 6d 61 [2] 62 7b [2] 7c 66 [2] 7e 67 [2] 65 61 [2] 79 66 [2] 65 49 }

  condition:
    any of them
}