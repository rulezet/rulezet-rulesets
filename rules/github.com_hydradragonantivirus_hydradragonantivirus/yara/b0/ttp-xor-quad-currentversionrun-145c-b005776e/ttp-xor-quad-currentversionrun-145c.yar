rule TTP_XOR_QUAD_CurrentVersionRun_145c {
  strings:
    $key_145c = { 47 33 [2] 63 3d [2] 48 11 [2] 66 33 [2] 72 28 [2] 7d 32 [2] 63 2f [2] 61 2e [2] 7a 28 [2] 66 2f [2] 7a 00 }

  condition:
    any of them
}