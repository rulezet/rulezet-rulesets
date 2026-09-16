rule TTP_XOR_QUAD_CurrentVersionRun_0b38 {
  strings:
    $key_0b38 = { 58 57 [2] 7c 59 [2] 57 75 [2] 79 57 [2] 6d 4c [2] 62 56 [2] 7c 4b [2] 7e 4a [2] 65 4c [2] 79 4b [2] 65 64 }

  condition:
    any of them
}