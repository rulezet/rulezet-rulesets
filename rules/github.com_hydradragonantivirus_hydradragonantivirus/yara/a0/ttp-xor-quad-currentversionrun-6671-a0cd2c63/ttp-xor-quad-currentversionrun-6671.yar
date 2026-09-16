rule TTP_XOR_QUAD_CurrentVersionRun_6671 {
  strings:
    $key_6671 = { 35 1e [2] 11 10 [2] 3a 3c [2] 14 1e [2] 00 05 [2] 0f 1f [2] 11 02 [2] 13 03 [2] 08 05 [2] 14 02 [2] 08 2d }

  condition:
    any of them
}