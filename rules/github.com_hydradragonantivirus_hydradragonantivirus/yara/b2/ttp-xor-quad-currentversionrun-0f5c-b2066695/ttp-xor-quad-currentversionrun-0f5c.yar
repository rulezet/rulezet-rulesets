rule TTP_XOR_QUAD_CurrentVersionRun_0f5c {
  strings:
    $key_0f5c = { 5c 33 [2] 78 3d [2] 53 11 [2] 7d 33 [2] 69 28 [2] 66 32 [2] 78 2f [2] 7a 2e [2] 61 28 [2] 7d 2f [2] 61 00 }

  condition:
    any of them
}