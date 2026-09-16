rule TTP_XOR_QUAD_CurrentVersionRun_035d {
  strings:
    $key_035d = { 50 32 [2] 74 3c [2] 5f 10 [2] 71 32 [2] 65 29 [2] 6a 33 [2] 74 2e [2] 76 2f [2] 6d 29 [2] 71 2e [2] 6d 01 }

  condition:
    any of them
}