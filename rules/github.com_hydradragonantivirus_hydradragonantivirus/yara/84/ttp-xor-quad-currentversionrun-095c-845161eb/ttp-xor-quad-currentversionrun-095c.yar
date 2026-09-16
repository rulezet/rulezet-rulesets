rule TTP_XOR_QUAD_CurrentVersionRun_095c {
  strings:
    $key_095c = { 5a 33 [2] 7e 3d [2] 55 11 [2] 7b 33 [2] 6f 28 [2] 60 32 [2] 7e 2f [2] 7c 2e [2] 67 28 [2] 7b 2f [2] 67 00 }

  condition:
    any of them
}