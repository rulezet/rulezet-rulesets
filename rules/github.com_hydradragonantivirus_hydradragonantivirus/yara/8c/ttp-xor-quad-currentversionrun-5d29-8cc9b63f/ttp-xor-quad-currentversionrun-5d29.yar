rule TTP_XOR_QUAD_CurrentVersionRun_5d29 {
  strings:
    $key_5d29 = { 0e 46 [2] 2a 48 [2] 01 64 [2] 2f 46 [2] 3b 5d [2] 34 47 [2] 2a 5a [2] 28 5b [2] 33 5d [2] 2f 5a [2] 33 75 }

  condition:
    any of them
}