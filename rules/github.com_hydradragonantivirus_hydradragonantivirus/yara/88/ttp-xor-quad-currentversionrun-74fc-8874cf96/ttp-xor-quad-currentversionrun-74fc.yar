rule TTP_XOR_QUAD_CurrentVersionRun_74fc {
  strings:
    $key_74fc = { 27 93 [2] 03 9d [2] 28 b1 [2] 06 93 [2] 12 88 [2] 1d 92 [2] 03 8f [2] 01 8e [2] 1a 88 [2] 06 8f [2] 1a a0 }

  condition:
    any of them
}