rule TTP_XOR_QUAD_CurrentVersionRun_295c {
  strings:
    $key_295c = { 7a 33 [2] 5e 3d [2] 75 11 [2] 5b 33 [2] 4f 28 [2] 40 32 [2] 5e 2f [2] 5c 2e [2] 47 28 [2] 5b 2f [2] 47 00 }

  condition:
    any of them
}