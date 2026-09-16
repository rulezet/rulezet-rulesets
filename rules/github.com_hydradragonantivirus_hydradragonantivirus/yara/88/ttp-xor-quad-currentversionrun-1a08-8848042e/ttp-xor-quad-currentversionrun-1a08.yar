rule TTP_XOR_QUAD_CurrentVersionRun_1a08 {
  strings:
    $key_1a08 = { 49 67 [2] 6d 69 [2] 46 45 [2] 68 67 [2] 7c 7c [2] 73 66 [2] 6d 7b [2] 6f 7a [2] 74 7c [2] 68 7b [2] 74 54 }

  condition:
    any of them
}