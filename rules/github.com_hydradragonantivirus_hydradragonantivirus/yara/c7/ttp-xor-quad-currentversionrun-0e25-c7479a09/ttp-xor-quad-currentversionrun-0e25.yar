rule TTP_XOR_QUAD_CurrentVersionRun_0e25 {
  strings:
    $key_0e25 = { 5d 4a [2] 79 44 [2] 52 68 [2] 7c 4a [2] 68 51 [2] 67 4b [2] 79 56 [2] 7b 57 [2] 60 51 [2] 7c 56 [2] 60 79 }

  condition:
    any of them
}