rule TTP_XOR_QUAD_CurrentVersionRun_5f7d {
  strings:
    $key_5f7d = { 0c 12 [2] 28 1c [2] 03 30 [2] 2d 12 [2] 39 09 [2] 36 13 [2] 28 0e [2] 2a 0f [2] 31 09 [2] 2d 0e [2] 31 21 }

  condition:
    any of them
}