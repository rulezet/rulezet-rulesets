rule TTP_XOR_QUAD_CurrentVersionRun_6771 {
  strings:
    $key_6771 = { 34 1e [2] 10 10 [2] 3b 3c [2] 15 1e [2] 01 05 [2] 0e 1f [2] 10 02 [2] 12 03 [2] 09 05 [2] 15 02 [2] 09 2d }

  condition:
    any of them
}