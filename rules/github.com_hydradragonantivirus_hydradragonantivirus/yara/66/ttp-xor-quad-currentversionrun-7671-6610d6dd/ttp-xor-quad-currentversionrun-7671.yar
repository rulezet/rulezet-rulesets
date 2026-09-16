rule TTP_XOR_QUAD_CurrentVersionRun_7671 {
  strings:
    $key_7671 = { 25 1e [2] 01 10 [2] 2a 3c [2] 04 1e [2] 10 05 [2] 1f 1f [2] 01 02 [2] 03 03 [2] 18 05 [2] 04 02 [2] 18 2d }

  condition:
    any of them
}