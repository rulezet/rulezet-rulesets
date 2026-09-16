rule TTP_XOR_QUAD_CurrentVersionRun_265d {
  strings:
    $key_265d = { 75 32 [2] 51 3c [2] 7a 10 [2] 54 32 [2] 40 29 [2] 4f 33 [2] 51 2e [2] 53 2f [2] 48 29 [2] 54 2e [2] 48 01 }

  condition:
    any of them
}