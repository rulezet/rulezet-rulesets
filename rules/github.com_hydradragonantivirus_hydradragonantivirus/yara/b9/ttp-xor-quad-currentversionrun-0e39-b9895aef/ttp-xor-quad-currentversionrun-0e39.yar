rule TTP_XOR_QUAD_CurrentVersionRun_0e39 {
  strings:
    $key_0e39 = { 5d 56 [2] 79 58 [2] 52 74 [2] 7c 56 [2] 68 4d [2] 67 57 [2] 79 4a [2] 7b 4b [2] 60 4d [2] 7c 4a [2] 60 65 }

  condition:
    any of them
}