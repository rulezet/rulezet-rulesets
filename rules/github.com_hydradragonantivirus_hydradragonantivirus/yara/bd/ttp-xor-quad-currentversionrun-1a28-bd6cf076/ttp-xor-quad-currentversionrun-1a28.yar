rule TTP_XOR_QUAD_CurrentVersionRun_1a28 {
  strings:
    $key_1a28 = { 49 47 [2] 6d 49 [2] 46 65 [2] 68 47 [2] 7c 5c [2] 73 46 [2] 6d 5b [2] 6f 5a [2] 74 5c [2] 68 5b [2] 74 74 }

  condition:
    any of them
}