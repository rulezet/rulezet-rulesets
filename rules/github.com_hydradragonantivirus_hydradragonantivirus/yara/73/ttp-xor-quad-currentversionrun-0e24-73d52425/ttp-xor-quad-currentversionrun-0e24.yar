rule TTP_XOR_QUAD_CurrentVersionRun_0e24 {
  strings:
    $key_0e24 = { 5d 4b [2] 79 45 [2] 52 69 [2] 7c 4b [2] 68 50 [2] 67 4a [2] 79 57 [2] 7b 56 [2] 60 50 [2] 7c 57 [2] 60 78 }

  condition:
    any of them
}