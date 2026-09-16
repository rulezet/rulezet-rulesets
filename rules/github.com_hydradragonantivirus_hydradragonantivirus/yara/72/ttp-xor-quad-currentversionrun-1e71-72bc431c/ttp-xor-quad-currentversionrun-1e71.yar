rule TTP_XOR_QUAD_CurrentVersionRun_1e71 {
  strings:
    $key_1e71 = { 4d 1e [2] 69 10 [2] 42 3c [2] 6c 1e [2] 78 05 [2] 77 1f [2] 69 02 [2] 6b 03 [2] 70 05 [2] 6c 02 [2] 70 2d }

  condition:
    any of them
}