rule TTP_XOR_QUAD_CurrentVersionRun_0e71 {
  strings:
    $key_0e71 = { 5d 1e [2] 79 10 [2] 52 3c [2] 7c 1e [2] 68 05 [2] 67 1f [2] 79 02 [2] 7b 03 [2] 60 05 [2] 7c 02 [2] 60 2d }

  condition:
    any of them
}