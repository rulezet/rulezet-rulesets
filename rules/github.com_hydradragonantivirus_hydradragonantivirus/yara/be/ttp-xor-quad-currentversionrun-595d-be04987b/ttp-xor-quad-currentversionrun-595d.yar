rule TTP_XOR_QUAD_CurrentVersionRun_595d {
  strings:
    $key_595d = { 0a 32 [2] 2e 3c [2] 05 10 [2] 2b 32 [2] 3f 29 [2] 30 33 [2] 2e 2e [2] 2c 2f [2] 37 29 [2] 2b 2e [2] 37 01 }

  condition:
    any of them
}