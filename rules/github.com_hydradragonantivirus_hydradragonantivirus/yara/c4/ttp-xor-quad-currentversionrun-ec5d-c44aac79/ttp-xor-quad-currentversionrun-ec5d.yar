rule TTP_XOR_QUAD_CurrentVersionRun_ec5d {
  strings:
    $key_ec5d = { bf 32 [2] 9b 3c [2] b0 10 [2] 9e 32 [2] 8a 29 [2] 85 33 [2] 9b 2e [2] 99 2f [2] 82 29 [2] 9e 2e [2] 82 01 }

  condition:
    any of them
}