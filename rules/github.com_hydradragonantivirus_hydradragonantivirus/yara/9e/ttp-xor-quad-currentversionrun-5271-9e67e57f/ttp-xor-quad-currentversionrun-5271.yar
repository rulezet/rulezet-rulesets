rule TTP_XOR_QUAD_CurrentVersionRun_5271 {
  strings:
    $key_5271 = { 01 1e [2] 25 10 [2] 0e 3c [2] 20 1e [2] 34 05 [2] 3b 1f [2] 25 02 [2] 27 03 [2] 3c 05 [2] 20 02 [2] 3c 2d }

  condition:
    any of them
}