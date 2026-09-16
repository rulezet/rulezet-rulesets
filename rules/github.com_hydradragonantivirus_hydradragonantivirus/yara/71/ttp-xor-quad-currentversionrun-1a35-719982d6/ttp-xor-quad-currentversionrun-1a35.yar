rule TTP_XOR_QUAD_CurrentVersionRun_1a35 {
  strings:
    $key_1a35 = { 49 5a [2] 6d 54 [2] 46 78 [2] 68 5a [2] 7c 41 [2] 73 5b [2] 6d 46 [2] 6f 47 [2] 74 41 [2] 68 46 [2] 74 69 }

  condition:
    any of them
}