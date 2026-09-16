rule TTP_XOR_QUAD_CurrentVersionRun_247b {
  strings:
    $key_247b = { 77 14 [2] 53 1a [2] 78 36 [2] 56 14 [2] 42 0f [2] 4d 15 [2] 53 08 [2] 51 09 [2] 4a 0f [2] 56 08 [2] 4a 27 }

  condition:
    any of them
}