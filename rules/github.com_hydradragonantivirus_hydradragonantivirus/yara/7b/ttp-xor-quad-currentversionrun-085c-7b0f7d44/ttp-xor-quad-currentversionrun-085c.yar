rule TTP_XOR_QUAD_CurrentVersionRun_085c {
  strings:
    $key_085c = { 5b 33 [2] 7f 3d [2] 54 11 [2] 7a 33 [2] 6e 28 [2] 61 32 [2] 7f 2f [2] 7d 2e [2] 66 28 [2] 7a 2f [2] 66 00 }

  condition:
    any of them
}