rule TTP_XOR_QUAD_CurrentVersionRun_4c29 {
  strings:
    $key_4c29 = { 1f 46 [2] 3b 48 [2] 10 64 [2] 3e 46 [2] 2a 5d [2] 25 47 [2] 3b 5a [2] 39 5b [2] 22 5d [2] 3e 5a [2] 22 75 }

  condition:
    any of them
}