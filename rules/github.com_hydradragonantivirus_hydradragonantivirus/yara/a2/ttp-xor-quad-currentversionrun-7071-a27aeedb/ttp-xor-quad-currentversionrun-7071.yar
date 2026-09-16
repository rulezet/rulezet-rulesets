rule TTP_XOR_QUAD_CurrentVersionRun_7071 {
  strings:
    $key_7071 = { 23 1e [2] 07 10 [2] 2c 3c [2] 02 1e [2] 16 05 [2] 19 1f [2] 07 02 [2] 05 03 [2] 1e 05 [2] 02 02 [2] 1e 2d }

  condition:
    any of them
}