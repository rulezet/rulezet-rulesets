rule TTP_XOR_QUAD_CurrentVersionRun_7a2b {
  strings:
    $key_7a2b = { 29 44 [2] 0d 4a [2] 26 66 [2] 08 44 [2] 1c 5f [2] 13 45 [2] 0d 58 [2] 0f 59 [2] 14 5f [2] 08 58 [2] 14 77 }

  condition:
    any of them
}