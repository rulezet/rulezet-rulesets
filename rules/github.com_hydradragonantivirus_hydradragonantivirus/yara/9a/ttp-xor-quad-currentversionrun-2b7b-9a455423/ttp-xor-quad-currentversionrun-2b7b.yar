rule TTP_XOR_QUAD_CurrentVersionRun_2b7b {
  strings:
    $key_2b7b = { 78 14 [2] 5c 1a [2] 77 36 [2] 59 14 [2] 4d 0f [2] 42 15 [2] 5c 08 [2] 5e 09 [2] 45 0f [2] 59 08 [2] 45 27 }

  condition:
    any of them
}