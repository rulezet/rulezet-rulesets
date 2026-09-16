rule TTP_XOR_QUAD_CurrentVersionRun_5afc {
  strings:
    $key_5afc = { 09 93 [2] 2d 9d [2] 06 b1 [2] 28 93 [2] 3c 88 [2] 33 92 [2] 2d 8f [2] 2f 8e [2] 34 88 [2] 28 8f [2] 34 a0 }

  condition:
    any of them
}