rule TTP_XOR_QUAD_CurrentVersionRun_7b7d {
  strings:
    $key_7b7d = { 28 12 [2] 0c 1c [2] 27 30 [2] 09 12 [2] 1d 09 [2] 12 13 [2] 0c 0e [2] 0e 0f [2] 15 09 [2] 09 0e [2] 15 21 }

  condition:
    any of them
}