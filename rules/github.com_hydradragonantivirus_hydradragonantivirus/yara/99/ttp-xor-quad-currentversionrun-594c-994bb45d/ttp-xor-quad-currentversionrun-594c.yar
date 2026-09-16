rule TTP_XOR_QUAD_CurrentVersionRun_594c {
  strings:
    $key_594c = { 0a 23 [2] 2e 2d [2] 05 01 [2] 2b 23 [2] 3f 38 [2] 30 22 [2] 2e 3f [2] 2c 3e [2] 37 38 [2] 2b 3f [2] 37 10 }

  condition:
    any of them
}