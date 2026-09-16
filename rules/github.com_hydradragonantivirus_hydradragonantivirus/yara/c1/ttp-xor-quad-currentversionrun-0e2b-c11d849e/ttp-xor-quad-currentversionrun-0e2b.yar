rule TTP_XOR_QUAD_CurrentVersionRun_0e2b {
  strings:
    $key_0e2b = { 5d 44 [2] 79 4a [2] 52 66 [2] 7c 44 [2] 68 5f [2] 67 45 [2] 79 58 [2] 7b 59 [2] 60 5f [2] 7c 58 [2] 60 77 }

  condition:
    any of them
}