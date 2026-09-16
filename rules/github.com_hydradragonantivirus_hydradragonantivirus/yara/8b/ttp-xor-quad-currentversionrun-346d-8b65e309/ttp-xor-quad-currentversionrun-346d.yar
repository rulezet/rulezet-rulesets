rule TTP_XOR_QUAD_CurrentVersionRun_346d {
  strings:
    $key_346d = { 67 02 [2] 43 0c [2] 68 20 [2] 46 02 [2] 52 19 [2] 5d 03 [2] 43 1e [2] 41 1f [2] 5a 19 [2] 46 1e [2] 5a 31 }

  condition:
    any of them
}