rule TTP_XOR_QUAD_CurrentVersionRun_0b4b {
  strings:
    $key_0b4b = { 58 24 [2] 7c 2a [2] 57 06 [2] 79 24 [2] 6d 3f [2] 62 25 [2] 7c 38 [2] 7e 39 [2] 65 3f [2] 79 38 [2] 65 17 }

  condition:
    any of them
}