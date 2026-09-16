rule TTP_XOR_QUAD_CurrentVersionRun_7e0b {
  strings:
    $key_7e0b = { 2d 64 [2] 09 6a [2] 22 46 [2] 0c 64 [2] 18 7f [2] 17 65 [2] 09 78 [2] 0b 79 [2] 10 7f [2] 0c 78 [2] 10 57 }

  condition:
    any of them
}