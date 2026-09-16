rule TTP_XOR_QUAD_CurrentVersionRun_1961 {
  strings:
    $key_1961 = { 4a 0e [2] 6e 00 [2] 45 2c [2] 6b 0e [2] 7f 15 [2] 70 0f [2] 6e 12 [2] 6c 13 [2] 77 15 [2] 6b 12 [2] 77 3d }

  condition:
    any of them
}