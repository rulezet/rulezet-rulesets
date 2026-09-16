rule TTP_XOR_QUAD_CurrentVersionRun_7a27 {
  strings:
    $key_7a27 = { 29 48 [2] 0d 46 [2] 26 6a [2] 08 48 [2] 1c 53 [2] 13 49 [2] 0d 54 [2] 0f 55 [2] 14 53 [2] 08 54 [2] 14 7b }

  condition:
    any of them
}