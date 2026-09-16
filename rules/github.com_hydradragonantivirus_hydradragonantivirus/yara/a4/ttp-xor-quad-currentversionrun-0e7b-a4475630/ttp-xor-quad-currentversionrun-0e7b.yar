rule TTP_XOR_QUAD_CurrentVersionRun_0e7b {
  strings:
    $key_0e7b = { 5d 14 [2] 79 1a [2] 52 36 [2] 7c 14 [2] 68 0f [2] 67 15 [2] 79 08 [2] 7b 09 [2] 60 0f [2] 7c 08 [2] 60 27 }

  condition:
    any of them
}