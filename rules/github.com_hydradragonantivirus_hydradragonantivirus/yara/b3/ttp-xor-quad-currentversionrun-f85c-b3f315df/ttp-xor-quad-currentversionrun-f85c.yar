rule TTP_XOR_QUAD_CurrentVersionRun_f85c {
  strings:
    $key_f85c = { ab 33 [2] 8f 3d [2] a4 11 [2] 8a 33 [2] 9e 28 [2] 91 32 [2] 8f 2f [2] 8d 2e [2] 96 28 [2] 8a 2f [2] 96 00 }

  condition:
    any of them
}