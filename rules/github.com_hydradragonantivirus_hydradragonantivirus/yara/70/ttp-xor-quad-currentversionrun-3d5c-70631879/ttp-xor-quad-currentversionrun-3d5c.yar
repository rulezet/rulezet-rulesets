rule TTP_XOR_QUAD_CurrentVersionRun_3d5c {
  strings:
    $key_3d5c = { 6e 33 [2] 4a 3d [2] 61 11 [2] 4f 33 [2] 5b 28 [2] 54 32 [2] 4a 2f [2] 48 2e [2] 53 28 [2] 4f 2f [2] 53 00 }

  condition:
    any of them
}