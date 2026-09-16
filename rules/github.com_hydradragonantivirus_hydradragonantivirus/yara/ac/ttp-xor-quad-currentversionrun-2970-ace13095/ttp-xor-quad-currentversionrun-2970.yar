rule TTP_XOR_QUAD_CurrentVersionRun_2970 {
  strings:
    $key_2970 = { 7a 1f [2] 5e 11 [2] 75 3d [2] 5b 1f [2] 4f 04 [2] 40 1e [2] 5e 03 [2] 5c 02 [2] 47 04 [2] 5b 03 [2] 47 2c }

  condition:
    any of them
}