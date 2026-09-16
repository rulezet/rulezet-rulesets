rule TTP_XOR_QUAD_CurrentVersionRun_215c {
  strings:
    $key_215c = { 72 33 [2] 56 3d [2] 7d 11 [2] 53 33 [2] 47 28 [2] 48 32 [2] 56 2f [2] 54 2e [2] 4f 28 [2] 53 2f [2] 4f 00 }

  condition:
    any of them
}