rule TTP_XOR_QUAD_CurrentVersionRun_165c {
  strings:
    $key_165c = { 45 33 [2] 61 3d [2] 4a 11 [2] 64 33 [2] 70 28 [2] 7f 32 [2] 61 2f [2] 63 2e [2] 78 28 [2] 64 2f [2] 78 00 }

  condition:
    any of them
}