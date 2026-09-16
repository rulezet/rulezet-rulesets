rule TTP_XOR_QUAD_CurrentVersionRun_3e71 {
  strings:
    $key_3e71 = { 6d 1e [2] 49 10 [2] 62 3c [2] 4c 1e [2] 58 05 [2] 57 1f [2] 49 02 [2] 4b 03 [2] 50 05 [2] 4c 02 [2] 50 2d }

  condition:
    any of them
}