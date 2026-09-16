rule TTP_XOR_QUAD_CurrentVersionRun_4b7b {
  strings:
    $key_4b7b = { 18 14 [2] 3c 1a [2] 17 36 [2] 39 14 [2] 2d 0f [2] 22 15 [2] 3c 08 [2] 3e 09 [2] 25 0f [2] 39 08 [2] 25 27 }

  condition:
    any of them
}