rule TTP_XOR_QUAD_CurrentVersionRun_5770 {
  strings:
    $key_5770 = { 04 1f [2] 20 11 [2] 0b 3d [2] 25 1f [2] 31 04 [2] 3e 1e [2] 20 03 [2] 22 02 [2] 39 04 [2] 25 03 [2] 39 2c }

  condition:
    any of them
}