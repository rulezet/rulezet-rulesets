rule TTP_XOR_QUAD_CurrentVersionRun_675c {
  strings:
    $key_675c = { 34 33 [2] 10 3d [2] 3b 11 [2] 15 33 [2] 01 28 [2] 0e 32 [2] 10 2f [2] 12 2e [2] 09 28 [2] 15 2f [2] 09 00 }

  condition:
    any of them
}