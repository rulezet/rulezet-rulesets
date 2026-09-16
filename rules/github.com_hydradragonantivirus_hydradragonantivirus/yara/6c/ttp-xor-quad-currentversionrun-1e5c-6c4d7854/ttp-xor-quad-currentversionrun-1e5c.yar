rule TTP_XOR_QUAD_CurrentVersionRun_1e5c {
  strings:
    $key_1e5c = { 4d 33 [2] 69 3d [2] 42 11 [2] 6c 33 [2] 78 28 [2] 77 32 [2] 69 2f [2] 6b 2e [2] 70 28 [2] 6c 2f [2] 70 00 }

  condition:
    any of them
}