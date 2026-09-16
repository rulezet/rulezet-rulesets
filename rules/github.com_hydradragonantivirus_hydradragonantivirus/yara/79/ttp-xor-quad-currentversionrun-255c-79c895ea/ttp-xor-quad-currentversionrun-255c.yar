rule TTP_XOR_QUAD_CurrentVersionRun_255c {
  strings:
    $key_255c = { 76 33 [2] 52 3d [2] 79 11 [2] 57 33 [2] 43 28 [2] 4c 32 [2] 52 2f [2] 50 2e [2] 4b 28 [2] 57 2f [2] 4b 00 }

  condition:
    any of them
}