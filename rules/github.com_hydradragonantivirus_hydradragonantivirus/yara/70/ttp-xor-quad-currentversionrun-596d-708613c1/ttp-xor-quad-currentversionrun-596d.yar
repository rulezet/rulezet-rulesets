rule TTP_XOR_QUAD_CurrentVersionRun_596d {
  strings:
    $key_596d = { 0a 02 [2] 2e 0c [2] 05 20 [2] 2b 02 [2] 3f 19 [2] 30 03 [2] 2e 1e [2] 2c 1f [2] 37 19 [2] 2b 1e [2] 37 31 }

  condition:
    any of them
}