rule TTP_XOR_QUAD_CurrentVersionRun_1a15 {
  strings:
    $key_1a15 = { 49 7a [2] 6d 74 [2] 46 58 [2] 68 7a [2] 7c 61 [2] 73 7b [2] 6d 66 [2] 6f 67 [2] 74 61 [2] 68 66 [2] 74 49 }

  condition:
    any of them
}