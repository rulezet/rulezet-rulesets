rule TTP_XOR_QUAD_CurrentVersionRun_7e17 {
  strings:
    $key_7e17 = { 2d 78 [2] 09 76 [2] 22 5a [2] 0c 78 [2] 18 63 [2] 17 79 [2] 09 64 [2] 0b 65 [2] 10 63 [2] 0c 64 [2] 10 4b }

  condition:
    any of them
}