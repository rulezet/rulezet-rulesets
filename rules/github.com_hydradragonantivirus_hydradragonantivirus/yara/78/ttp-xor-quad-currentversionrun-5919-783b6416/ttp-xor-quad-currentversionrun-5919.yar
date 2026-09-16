rule TTP_XOR_QUAD_CurrentVersionRun_5919 {
  strings:
    $key_5919 = { 0a 76 [2] 2e 78 [2] 05 54 [2] 2b 76 [2] 3f 6d [2] 30 77 [2] 2e 6a [2] 2c 6b [2] 37 6d [2] 2b 6a [2] 37 45 }

  condition:
    any of them
}