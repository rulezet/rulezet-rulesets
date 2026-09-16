rule TTP_XOR_QUAD_CurrentVersionRun_465d {
  strings:
    $key_465d = { 15 32 [2] 31 3c [2] 1a 10 [2] 34 32 [2] 20 29 [2] 2f 33 [2] 31 2e [2] 33 2f [2] 28 29 [2] 34 2e [2] 28 01 }

  condition:
    any of them
}