rule TTP_XOR_QUAD_CurrentVersionRun_1c28 {
  strings:
    $key_1c28 = { 4f 47 [2] 6b 49 [2] 40 65 [2] 6e 47 [2] 7a 5c [2] 75 46 [2] 6b 5b [2] 69 5a [2] 72 5c [2] 6e 5b [2] 72 74 }

  condition:
    any of them
}