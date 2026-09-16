rule TTP_XOR_QUAD_CurrentVersionRun_5a6d {
  strings:
    $key_5a6d = { 09 02 [2] 2d 0c [2] 06 20 [2] 28 02 [2] 3c 19 [2] 33 03 [2] 2d 1e [2] 2f 1f [2] 34 19 [2] 28 1e [2] 34 31 }

  condition:
    any of them
}