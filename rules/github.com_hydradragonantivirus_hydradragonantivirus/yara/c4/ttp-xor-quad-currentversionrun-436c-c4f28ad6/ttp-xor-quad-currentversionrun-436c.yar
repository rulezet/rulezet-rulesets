rule TTP_XOR_QUAD_CurrentVersionRun_436c {
  strings:
    $key_436c = { 10 03 [2] 34 0d [2] 1f 21 [2] 31 03 [2] 25 18 [2] 2a 02 [2] 34 1f [2] 36 1e [2] 2d 18 [2] 31 1f [2] 2d 30 }

  condition:
    any of them
}