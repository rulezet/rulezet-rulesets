rule TTP_XOR_QUAD_CurrentVersionRun_5952 {
  strings:
    $key_5952 = { 0a 3d [2] 2e 33 [2] 05 1f [2] 2b 3d [2] 3f 26 [2] 30 3c [2] 2e 21 [2] 2c 20 [2] 37 26 [2] 2b 21 [2] 37 0e }

  condition:
    any of them
}