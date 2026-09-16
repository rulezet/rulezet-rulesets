rule TTP_XOR_QUAD_CurrentVersionRun_5241 {
  strings:
    $key_5241 = { 01 2e [2] 25 20 [2] 0e 0c [2] 20 2e [2] 34 35 [2] 3b 2f [2] 25 32 [2] 27 33 [2] 3c 35 [2] 20 32 [2] 3c 1d }

  condition:
    any of them
}