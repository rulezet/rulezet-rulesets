rule TTP_XOR_QUAD_CurrentVersionRun_1471 {
  strings:
    $key_1471 = { 47 1e [2] 63 10 [2] 48 3c [2] 66 1e [2] 72 05 [2] 7d 1f [2] 63 02 [2] 61 03 [2] 7a 05 [2] 66 02 [2] 7a 2d }

  condition:
    any of them
}