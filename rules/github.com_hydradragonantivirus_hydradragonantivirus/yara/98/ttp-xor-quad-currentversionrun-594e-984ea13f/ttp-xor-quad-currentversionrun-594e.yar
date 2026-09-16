rule TTP_XOR_QUAD_CurrentVersionRun_594e {
  strings:
    $key_594e = { 0a 21 [2] 2e 2f [2] 05 03 [2] 2b 21 [2] 3f 3a [2] 30 20 [2] 2e 3d [2] 2c 3c [2] 37 3a [2] 2b 3d [2] 37 12 }

  condition:
    any of them
}