rule TTP_XOR_QUAD_CurrentVersionRun_1d71 {
  strings:
    $key_1d71 = { 4e 1e [2] 6a 10 [2] 41 3c [2] 6f 1e [2] 7b 05 [2] 74 1f [2] 6a 02 [2] 68 03 [2] 73 05 [2] 6f 02 [2] 73 2d }

  condition:
    any of them
}