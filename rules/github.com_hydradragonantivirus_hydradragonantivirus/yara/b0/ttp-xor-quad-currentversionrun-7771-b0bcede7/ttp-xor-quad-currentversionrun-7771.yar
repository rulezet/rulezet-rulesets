rule TTP_XOR_QUAD_CurrentVersionRun_7771 {
  strings:
    $key_7771 = { 24 1e [2] 00 10 [2] 2b 3c [2] 05 1e [2] 11 05 [2] 1e 1f [2] 00 02 [2] 02 03 [2] 19 05 [2] 05 02 [2] 19 2d }

  condition:
    any of them
}