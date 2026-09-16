rule TTP_XOR_QUAD_CurrentVersionRun_6b7b {
  strings:
    $key_6b7b = { 38 14 [2] 1c 1a [2] 37 36 [2] 19 14 [2] 0d 0f [2] 02 15 [2] 1c 08 [2] 1e 09 [2] 05 0f [2] 19 08 [2] 05 27 }

  condition:
    any of them
}