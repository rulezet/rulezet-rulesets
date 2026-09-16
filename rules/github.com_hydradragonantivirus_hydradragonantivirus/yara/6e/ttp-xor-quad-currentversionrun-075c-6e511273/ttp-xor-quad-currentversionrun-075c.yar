rule TTP_XOR_QUAD_CurrentVersionRun_075c {
  strings:
    $key_075c = { 54 33 [2] 70 3d [2] 5b 11 [2] 75 33 [2] 61 28 [2] 6e 32 [2] 70 2f [2] 72 2e [2] 69 28 [2] 75 2f [2] 69 00 }

  condition:
    any of them
}