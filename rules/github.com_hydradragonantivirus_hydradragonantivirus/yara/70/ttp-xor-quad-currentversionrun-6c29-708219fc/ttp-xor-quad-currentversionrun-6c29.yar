rule TTP_XOR_QUAD_CurrentVersionRun_6c29 {
  strings:
    $key_6c29 = { 3f 46 [2] 1b 48 [2] 30 64 [2] 1e 46 [2] 0a 5d [2] 05 47 [2] 1b 5a [2] 19 5b [2] 02 5d [2] 1e 5a [2] 02 75 }

  condition:
    any of them
}