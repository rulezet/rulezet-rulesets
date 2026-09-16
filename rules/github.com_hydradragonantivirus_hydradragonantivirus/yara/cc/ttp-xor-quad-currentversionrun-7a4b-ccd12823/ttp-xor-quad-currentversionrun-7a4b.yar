rule TTP_XOR_QUAD_CurrentVersionRun_7a4b {
  strings:
    $key_7a4b = { 29 24 [2] 0d 2a [2] 26 06 [2] 08 24 [2] 1c 3f [2] 13 25 [2] 0d 38 [2] 0f 39 [2] 14 3f [2] 08 38 [2] 14 17 }

  condition:
    any of them
}