rule TTP_XOR_QUAD_CurrentVersionRun_447b {
  strings:
    $key_447b = { 17 14 [2] 33 1a [2] 18 36 [2] 36 14 [2] 22 0f [2] 2d 15 [2] 33 08 [2] 31 09 [2] 2a 0f [2] 36 08 [2] 2a 27 }

  condition:
    any of them
}