rule TTP_XOR_QUAD_CurrentVersionRun_7e7b {
  strings:
    $key_7e7b = { 2d 14 [2] 09 1a [2] 22 36 [2] 0c 14 [2] 18 0f [2] 17 15 [2] 09 08 [2] 0b 09 [2] 10 0f [2] 0c 08 [2] 10 27 }

  condition:
    any of them
}