rule TTP_XOR_QUAD_CurrentVersionRun_346c {
  strings:
    $key_346c = { 67 03 [2] 43 0d [2] 68 21 [2] 46 03 [2] 52 18 [2] 5d 02 [2] 43 1f [2] 41 1e [2] 5a 18 [2] 46 1f [2] 5a 30 }

  condition:
    any of them
}