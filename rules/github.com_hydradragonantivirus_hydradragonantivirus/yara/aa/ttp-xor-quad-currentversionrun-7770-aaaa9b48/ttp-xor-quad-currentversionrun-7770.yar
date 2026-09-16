rule TTP_XOR_QUAD_CurrentVersionRun_7770 {
  strings:
    $key_7770 = { 24 1f [2] 00 11 [2] 2b 3d [2] 05 1f [2] 11 04 [2] 1e 1e [2] 00 03 [2] 02 02 [2] 19 04 [2] 05 03 [2] 19 2c }

  condition:
    any of them
}