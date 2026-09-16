rule TTP_XOR_QUAD_CurrentVersionRun_0b39 {
  strings:
    $key_0b39 = { 58 56 [2] 7c 58 [2] 57 74 [2] 79 56 [2] 6d 4d [2] 62 57 [2] 7c 4a [2] 7e 4b [2] 65 4d [2] 79 4a [2] 65 65 }

  condition:
    any of them
}