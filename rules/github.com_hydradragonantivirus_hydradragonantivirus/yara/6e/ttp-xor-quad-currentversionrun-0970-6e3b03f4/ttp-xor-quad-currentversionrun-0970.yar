rule TTP_XOR_QUAD_CurrentVersionRun_0970 {
  strings:
    $key_0970 = { 5a 1f [2] 7e 11 [2] 55 3d [2] 7b 1f [2] 6f 04 [2] 60 1e [2] 7e 03 [2] 7c 02 [2] 67 04 [2] 7b 03 [2] 67 2c }

  condition:
    any of them
}