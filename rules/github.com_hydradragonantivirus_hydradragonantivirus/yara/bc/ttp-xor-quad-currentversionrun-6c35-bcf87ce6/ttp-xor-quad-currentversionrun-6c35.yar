rule TTP_XOR_QUAD_CurrentVersionRun_6c35 {
  strings:
    $key_6c35 = { 3f 5a [2] 1b 54 [2] 30 78 [2] 1e 5a [2] 0a 41 [2] 05 5b [2] 1b 46 [2] 19 47 [2] 02 41 [2] 1e 46 [2] 02 69 }

  condition:
    any of them
}