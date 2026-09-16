rule TTP_XOR_QUAD_CurrentVersionRun_3a71 {
  strings:
    $key_3a71 = { 69 1e [2] 4d 10 [2] 66 3c [2] 48 1e [2] 5c 05 [2] 53 1f [2] 4d 02 [2] 4f 03 [2] 54 05 [2] 48 02 [2] 54 2d }

  condition:
    any of them
}