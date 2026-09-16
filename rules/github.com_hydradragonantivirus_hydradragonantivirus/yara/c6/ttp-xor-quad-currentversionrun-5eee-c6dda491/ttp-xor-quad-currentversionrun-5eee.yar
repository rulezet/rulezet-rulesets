rule TTP_XOR_QUAD_CurrentVersionRun_5eee {
  strings:
    $key_5eee = { 0d 81 [2] 29 8f [2] 02 a3 [2] 2c 81 [2] 38 9a [2] 37 80 [2] 29 9d [2] 2b 9c [2] 30 9a [2] 2c 9d [2] 30 b2 }

  condition:
    any of them
}