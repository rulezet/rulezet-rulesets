rule TTP_XOR_QUAD_CurrentVersionRun_5ffb {
  strings:
    $key_5ffb = { 0c 94 [2] 28 9a [2] 03 b6 [2] 2d 94 [2] 39 8f [2] 36 95 [2] 28 88 [2] 2a 89 [2] 31 8f [2] 2d 88 [2] 31 a7 }

  condition:
    any of them
}