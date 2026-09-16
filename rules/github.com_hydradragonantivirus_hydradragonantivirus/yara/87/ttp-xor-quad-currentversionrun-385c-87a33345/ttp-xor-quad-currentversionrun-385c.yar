rule TTP_XOR_QUAD_CurrentVersionRun_385c {
  strings:
    $key_385c = { 6b 33 [2] 4f 3d [2] 64 11 [2] 4a 33 [2] 5e 28 [2] 51 32 [2] 4f 2f [2] 4d 2e [2] 56 28 [2] 4a 2f [2] 56 00 }

  condition:
    any of them
}