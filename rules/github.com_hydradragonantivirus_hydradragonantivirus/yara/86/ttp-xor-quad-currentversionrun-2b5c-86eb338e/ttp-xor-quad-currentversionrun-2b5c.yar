rule TTP_XOR_QUAD_CurrentVersionRun_2b5c {
  strings:
    $key_2b5c = { 78 33 [2] 5c 3d [2] 77 11 [2] 59 33 [2] 4d 28 [2] 42 32 [2] 5c 2f [2] 5e 2e [2] 45 28 [2] 59 2f [2] 45 00 }

  condition:
    any of them
}