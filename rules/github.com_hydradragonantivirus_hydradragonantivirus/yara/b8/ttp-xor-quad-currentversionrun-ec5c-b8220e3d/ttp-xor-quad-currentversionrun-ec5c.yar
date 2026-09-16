rule TTP_XOR_QUAD_CurrentVersionRun_ec5c {
  strings:
    $key_ec5c = { bf 33 [2] 9b 3d [2] b0 11 [2] 9e 33 [2] 8a 28 [2] 85 32 [2] 9b 2f [2] 99 2e [2] 82 28 [2] 9e 2f [2] 82 00 }

  condition:
    any of them
}