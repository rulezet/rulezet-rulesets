rule TTP_XOR_QUAD_CurrentVersionRun_355c {
  strings:
    $key_355c = { 66 33 [2] 42 3d [2] 69 11 [2] 47 33 [2] 53 28 [2] 5c 32 [2] 42 2f [2] 40 2e [2] 5b 28 [2] 47 2f [2] 5b 00 }

  condition:
    any of them
}