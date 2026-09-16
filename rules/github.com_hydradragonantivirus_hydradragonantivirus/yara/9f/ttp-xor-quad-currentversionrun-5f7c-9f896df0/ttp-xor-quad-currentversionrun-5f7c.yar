rule TTP_XOR_QUAD_CurrentVersionRun_5f7c {
  strings:
    $key_5f7c = { 0c 13 [2] 28 1d [2] 03 31 [2] 2d 13 [2] 39 08 [2] 36 12 [2] 28 0f [2] 2a 0e [2] 31 08 [2] 2d 0f [2] 31 20 }

  condition:
    any of them
}