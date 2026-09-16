rule TTP_XOR_QUAD_CurrentVersionRun_5066 {
  strings:
    $key_5066 = { 03 09 [2] 27 07 [2] 0c 2b [2] 22 09 [2] 36 12 [2] 39 08 [2] 27 15 [2] 25 14 [2] 3e 12 [2] 22 15 [2] 3e 3a }

  condition:
    any of them
}