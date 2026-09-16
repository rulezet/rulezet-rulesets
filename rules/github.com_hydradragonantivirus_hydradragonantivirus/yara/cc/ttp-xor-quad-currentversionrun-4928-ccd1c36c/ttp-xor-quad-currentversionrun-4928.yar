rule TTP_XOR_QUAD_CurrentVersionRun_4928 {
  strings:
    $key_4928 = { 1a 47 [2] 3e 49 [2] 15 65 [2] 3b 47 [2] 2f 5c [2] 20 46 [2] 3e 5b [2] 3c 5a [2] 27 5c [2] 3b 5b [2] 27 74 }

  condition:
    any of them
}