rule TTP_XOR_QUAD_CurrentVersionRun_2670 {
  strings:
    $key_2670 = { 75 1f [2] 51 11 [2] 7a 3d [2] 54 1f [2] 40 04 [2] 4f 1e [2] 51 03 [2] 53 02 [2] 48 04 [2] 54 03 [2] 48 2c }

  condition:
    any of them
}