rule TTP_XOR_QUAD_CurrentVersionRun_7a06 {
  strings:
    $key_7a06 = { 29 69 [2] 0d 67 [2] 26 4b [2] 08 69 [2] 1c 72 [2] 13 68 [2] 0d 75 [2] 0f 74 [2] 14 72 [2] 08 75 [2] 14 5a }

  condition:
    any of them
}