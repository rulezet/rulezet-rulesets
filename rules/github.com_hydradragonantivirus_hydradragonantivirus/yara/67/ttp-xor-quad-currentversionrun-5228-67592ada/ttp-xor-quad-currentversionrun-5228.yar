rule TTP_XOR_QUAD_CurrentVersionRun_5228 {
  strings:
    $key_5228 = { 01 47 [2] 25 49 [2] 0e 65 [2] 20 47 [2] 34 5c [2] 3b 46 [2] 25 5b [2] 27 5a [2] 3c 5c [2] 20 5b [2] 3c 74 }

  condition:
    any of them
}