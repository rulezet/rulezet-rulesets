rule TTP_XOR_QUAD_CurrentVersionRun_6b71 {
  strings:
    $key_6b71 = { 38 1e [2] 1c 10 [2] 37 3c [2] 19 1e [2] 0d 05 [2] 02 1f [2] 1c 02 [2] 1e 03 [2] 05 05 [2] 19 02 [2] 05 2d }

  condition:
    any of them
}