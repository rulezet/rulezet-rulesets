rule TTP_XOR_QUAD_CurrentVersionRun_7a56 {
  strings:
    $key_7a56 = { 29 39 [2] 0d 37 [2] 26 1b [2] 08 39 [2] 1c 22 [2] 13 38 [2] 0d 25 [2] 0f 24 [2] 14 22 [2] 08 25 [2] 14 0a }

  condition:
    any of them
}