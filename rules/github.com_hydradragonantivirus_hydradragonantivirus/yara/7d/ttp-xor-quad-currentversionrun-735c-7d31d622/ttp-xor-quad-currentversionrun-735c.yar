rule TTP_XOR_QUAD_CurrentVersionRun_735c {
  strings:
    $key_735c = { 20 33 [2] 04 3d [2] 2f 11 [2] 01 33 [2] 15 28 [2] 1a 32 [2] 04 2f [2] 06 2e [2] 1d 28 [2] 01 2f [2] 1d 00 }

  condition:
    any of them
}