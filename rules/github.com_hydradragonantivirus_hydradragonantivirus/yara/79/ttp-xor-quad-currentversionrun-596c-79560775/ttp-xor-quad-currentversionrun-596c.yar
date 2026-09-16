rule TTP_XOR_QUAD_CurrentVersionRun_596c {
  strings:
    $key_596c = { 0a 03 [2] 2e 0d [2] 05 21 [2] 2b 03 [2] 3f 18 [2] 30 02 [2] 2e 1f [2] 2c 1e [2] 37 18 [2] 2b 1f [2] 37 30 }

  condition:
    any of them
}