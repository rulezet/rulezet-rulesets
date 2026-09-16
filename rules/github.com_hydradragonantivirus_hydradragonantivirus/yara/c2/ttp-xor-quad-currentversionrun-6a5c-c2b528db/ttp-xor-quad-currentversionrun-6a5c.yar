rule TTP_XOR_QUAD_CurrentVersionRun_6a5c {
  strings:
    $key_6a5c = { 39 33 [2] 1d 3d [2] 36 11 [2] 18 33 [2] 0c 28 [2] 03 32 [2] 1d 2f [2] 1f 2e [2] 04 28 [2] 18 2f [2] 04 00 }

  condition:
    any of them
}