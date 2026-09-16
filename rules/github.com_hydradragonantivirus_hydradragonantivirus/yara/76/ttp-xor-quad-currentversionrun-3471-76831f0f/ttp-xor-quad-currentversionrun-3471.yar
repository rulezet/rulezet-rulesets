rule TTP_XOR_QUAD_CurrentVersionRun_3471 {
  strings:
    $key_3471 = { 67 1e [2] 43 10 [2] 68 3c [2] 46 1e [2] 52 05 [2] 5d 1f [2] 43 02 [2] 41 03 [2] 5a 05 [2] 46 02 [2] 5a 2d }

  condition:
    any of them
}