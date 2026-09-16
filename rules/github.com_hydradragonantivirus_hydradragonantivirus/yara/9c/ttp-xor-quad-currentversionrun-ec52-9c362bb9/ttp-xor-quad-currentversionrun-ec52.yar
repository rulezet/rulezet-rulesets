rule TTP_XOR_QUAD_CurrentVersionRun_ec52 {
  strings:
    $key_ec52 = { bf 3d [2] 9b 33 [2] b0 1f [2] 9e 3d [2] 8a 26 [2] 85 3c [2] 9b 21 [2] 99 20 [2] 82 26 [2] 9e 21 [2] 82 0e }

  condition:
    any of them
}