rule TTP_XOR_QUAD_CurrentVersionRun_240b {
  strings:
    $key_240b = { 77 64 [2] 53 6a [2] 78 46 [2] 56 64 [2] 42 7f [2] 4d 65 [2] 53 78 [2] 51 79 [2] 4a 7f [2] 56 78 [2] 4a 57 }

  condition:
    any of them
}