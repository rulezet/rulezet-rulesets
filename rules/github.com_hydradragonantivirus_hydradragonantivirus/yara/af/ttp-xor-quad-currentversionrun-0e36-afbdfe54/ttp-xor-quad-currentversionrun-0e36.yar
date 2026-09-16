rule TTP_XOR_QUAD_CurrentVersionRun_0e36 {
  strings:
    $key_0e36 = { 5d 59 [2] 79 57 [2] 52 7b [2] 7c 59 [2] 68 42 [2] 67 58 [2] 79 45 [2] 7b 44 [2] 60 42 [2] 7c 45 [2] 60 6a }

  condition:
    any of them
}