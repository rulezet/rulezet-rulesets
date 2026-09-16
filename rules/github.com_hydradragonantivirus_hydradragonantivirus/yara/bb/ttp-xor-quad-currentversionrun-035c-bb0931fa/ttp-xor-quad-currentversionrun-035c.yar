rule TTP_XOR_QUAD_CurrentVersionRun_035c {
  strings:
    $key_035c = { 50 33 [2] 74 3d [2] 5f 11 [2] 71 33 [2] 65 28 [2] 6a 32 [2] 74 2f [2] 76 2e [2] 6d 28 [2] 71 2f [2] 6d 00 }

  condition:
    any of them
}