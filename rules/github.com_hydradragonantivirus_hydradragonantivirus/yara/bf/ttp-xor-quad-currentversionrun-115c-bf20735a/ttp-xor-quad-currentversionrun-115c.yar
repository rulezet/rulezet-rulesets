rule TTP_XOR_QUAD_CurrentVersionRun_115c {
  strings:
    $key_115c = { 42 33 [2] 66 3d [2] 4d 11 [2] 63 33 [2] 77 28 [2] 78 32 [2] 66 2f [2] 64 2e [2] 7f 28 [2] 63 2f [2] 7f 00 }

  condition:
    any of them
}