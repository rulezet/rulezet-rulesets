rule TTP_XOR_QUAD_CurrentVersionRun_0c0b {
  strings:
    $key_0c0b = { 5f 64 [2] 7b 6a [2] 50 46 [2] 7e 64 [2] 6a 7f [2] 65 65 [2] 7b 78 [2] 79 79 [2] 62 7f [2] 7e 78 [2] 62 57 }

  condition:
    any of them
}