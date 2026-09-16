rule TTP_XOR_QUAD_CurrentVersionRun_2a28 {
  strings:
    $key_2a28 = { 79 47 [2] 5d 49 [2] 76 65 [2] 58 47 [2] 4c 5c [2] 43 46 [2] 5d 5b [2] 5f 5a [2] 44 5c [2] 58 5b [2] 44 74 }

  condition:
    any of them
}