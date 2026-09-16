rule TTP_XOR_QUAD_CurrentVersionRun_0a5c {
  strings:
    $key_0a5c = { 59 33 [2] 7d 3d [2] 56 11 [2] 78 33 [2] 6c 28 [2] 63 32 [2] 7d 2f [2] 7f 2e [2] 64 28 [2] 78 2f [2] 64 00 }

  condition:
    any of them
}