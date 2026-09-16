rule TTP_XOR_QUAD_CurrentVersionRun_1a74 {
  strings:
    $key_1a74 = { 49 1b [2] 6d 15 [2] 46 39 [2] 68 1b [2] 7c 00 [2] 73 1a [2] 6d 07 [2] 6f 06 [2] 74 00 [2] 68 07 [2] 74 28 }

  condition:
    any of them
}