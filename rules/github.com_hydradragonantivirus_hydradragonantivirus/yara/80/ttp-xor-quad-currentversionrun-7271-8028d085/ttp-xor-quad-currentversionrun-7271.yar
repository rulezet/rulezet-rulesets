rule TTP_XOR_QUAD_CurrentVersionRun_7271 {
  strings:
    $key_7271 = { 21 1e [2] 05 10 [2] 2e 3c [2] 00 1e [2] 14 05 [2] 1b 1f [2] 05 02 [2] 07 03 [2] 1c 05 [2] 00 02 [2] 1c 2d }

  condition:
    any of them
}