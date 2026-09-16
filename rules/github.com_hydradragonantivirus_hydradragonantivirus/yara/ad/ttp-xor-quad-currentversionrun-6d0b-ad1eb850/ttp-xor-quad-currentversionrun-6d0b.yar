rule TTP_XOR_QUAD_CurrentVersionRun_6d0b {
  strings:
    $key_6d0b = { 3e 64 [2] 1a 6a [2] 31 46 [2] 1f 64 [2] 0b 7f [2] 04 65 [2] 1a 78 [2] 18 79 [2] 03 7f [2] 1f 78 [2] 03 57 }

  condition:
    any of them
}