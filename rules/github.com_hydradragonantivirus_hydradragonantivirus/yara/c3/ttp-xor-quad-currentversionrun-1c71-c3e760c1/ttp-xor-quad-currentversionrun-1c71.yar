rule TTP_XOR_QUAD_CurrentVersionRun_1c71 {
  strings:
    $key_1c71 = { 4f 1e [2] 6b 10 [2] 40 3c [2] 6e 1e [2] 7a 05 [2] 75 1f [2] 6b 02 [2] 69 03 [2] 72 05 [2] 6e 02 [2] 72 2d }

  condition:
    any of them
}