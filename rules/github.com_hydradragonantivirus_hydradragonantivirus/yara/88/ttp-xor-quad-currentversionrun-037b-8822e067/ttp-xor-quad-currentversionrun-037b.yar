rule TTP_XOR_QUAD_CurrentVersionRun_037b {
  strings:
    $key_037b = { 50 14 [2] 74 1a [2] 5f 36 [2] 71 14 [2] 65 0f [2] 6a 15 [2] 74 08 [2] 76 09 [2] 6d 0f [2] 71 08 [2] 6d 27 }

  condition:
    any of them
}