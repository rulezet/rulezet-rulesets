rule TTP_XOR_QUAD_CurrentVersionRun_0c28 {
  strings:
    $key_0c28 = { 5f 47 [2] 7b 49 [2] 50 65 [2] 7e 47 [2] 6a 5c [2] 65 46 [2] 7b 5b [2] 79 5a [2] 62 5c [2] 7e 5b [2] 62 74 }

  condition:
    any of them
}