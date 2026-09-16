rule TTP_XOR_QUAD_CurrentVersionRun_517c {
  strings:
    $key_517c = { 02 13 [2] 26 1d [2] 0d 31 [2] 23 13 [2] 37 08 [2] 38 12 [2] 26 0f [2] 24 0e [2] 3f 08 [2] 23 0f [2] 3f 20 }

  condition:
    any of them
}