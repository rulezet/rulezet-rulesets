rule TTP_XOR_QUAD_CurrentVersionRun_5a0c {
  strings:
    $key_5a0c = { 09 63 [2] 2d 6d [2] 06 41 [2] 28 63 [2] 3c 78 [2] 33 62 [2] 2d 7f [2] 2f 7e [2] 34 78 [2] 28 7f [2] 34 50 }

  condition:
    any of them
}