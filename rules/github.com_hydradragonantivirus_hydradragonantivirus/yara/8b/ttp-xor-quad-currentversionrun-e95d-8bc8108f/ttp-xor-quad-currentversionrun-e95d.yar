rule TTP_XOR_QUAD_CurrentVersionRun_e95d {
  strings:
    $key_e95d = { ba 32 [2] 9e 3c [2] b5 10 [2] 9b 32 [2] 8f 29 [2] 80 33 [2] 9e 2e [2] 9c 2f [2] 87 29 [2] 9b 2e [2] 87 01 }

  condition:
    any of them
}