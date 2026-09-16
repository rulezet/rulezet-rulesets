rule TTP_XOR_QUAD_CurrentVersionRun_1a19 {
  strings:
    $key_1a19 = { 49 76 [2] 6d 78 [2] 46 54 [2] 68 76 [2] 7c 6d [2] 73 77 [2] 6d 6a [2] 6f 6b [2] 74 6d [2] 68 6a [2] 74 45 }

  condition:
    any of them
}