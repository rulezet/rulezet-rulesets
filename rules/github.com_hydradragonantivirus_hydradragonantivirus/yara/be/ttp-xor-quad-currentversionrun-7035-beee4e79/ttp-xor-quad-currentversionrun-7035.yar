rule TTP_XOR_QUAD_CurrentVersionRun_7035 {
  strings:
    $key_7035 = { 23 5a [2] 07 54 [2] 2c 78 [2] 02 5a [2] 16 41 [2] 19 5b [2] 07 46 [2] 05 47 [2] 1e 41 [2] 02 46 [2] 1e 69 }

  condition:
    any of them
}