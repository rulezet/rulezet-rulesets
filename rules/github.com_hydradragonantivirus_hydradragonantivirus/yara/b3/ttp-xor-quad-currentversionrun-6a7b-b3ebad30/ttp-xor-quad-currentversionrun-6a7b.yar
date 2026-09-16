rule TTP_XOR_QUAD_CurrentVersionRun_6a7b {
  strings:
    $key_6a7b = { 39 14 [2] 1d 1a [2] 36 36 [2] 18 14 [2] 0c 0f [2] 03 15 [2] 1d 08 [2] 1f 09 [2] 04 0f [2] 18 08 [2] 04 27 }

  condition:
    any of them
}