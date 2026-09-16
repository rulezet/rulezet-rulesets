rule TTP_XOR_QUAD_CurrentVersionRun_2e7b {
  strings:
    $key_2e7b = { 7d 14 [2] 59 1a [2] 72 36 [2] 5c 14 [2] 48 0f [2] 47 15 [2] 59 08 [2] 5b 09 [2] 40 0f [2] 5c 08 [2] 40 27 }

  condition:
    any of them
}