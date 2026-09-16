rule TTP_XOR_QUAD_CurrentVersionRun_045c {
  strings:
    $key_045c = { 57 33 [2] 73 3d [2] 58 11 [2] 76 33 [2] 62 28 [2] 6d 32 [2] 73 2f [2] 71 2e [2] 6a 28 [2] 76 2f [2] 6a 00 }

  condition:
    any of them
}