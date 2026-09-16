rule TTP_XOR_QUAD_CurrentVersionRun_0270 {
  strings:
    $key_0270 = { 51 1f [2] 75 11 [2] 5e 3d [2] 70 1f [2] 64 04 [2] 6b 1e [2] 75 03 [2] 77 02 [2] 6c 04 [2] 70 03 [2] 6c 2c }

  condition:
    any of them
}