rule TTP_XOR_QUAD_CurrentVersionRun_0b24 {
  strings:
    $key_0b24 = { 58 4b [2] 7c 45 [2] 57 69 [2] 79 4b [2] 6d 50 [2] 62 4a [2] 7c 57 [2] 7e 56 [2] 65 50 [2] 79 57 [2] 65 78 }

  condition:
    any of them
}