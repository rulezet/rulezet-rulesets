rule TTP_XOR_QUAD_CurrentVersionRun_2d0b {
  strings:
    $key_2d0b = { 7e 64 [2] 5a 6a [2] 71 46 [2] 5f 64 [2] 4b 7f [2] 44 65 [2] 5a 78 [2] 58 79 [2] 43 7f [2] 5f 78 [2] 43 57 }

  condition:
    any of them
}