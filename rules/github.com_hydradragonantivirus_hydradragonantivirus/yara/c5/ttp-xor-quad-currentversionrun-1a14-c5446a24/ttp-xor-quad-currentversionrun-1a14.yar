rule TTP_XOR_QUAD_CurrentVersionRun_1a14 {
  strings:
    $key_1a14 = { 49 7b [2] 6d 75 [2] 46 59 [2] 68 7b [2] 7c 60 [2] 73 7a [2] 6d 67 [2] 6f 66 [2] 74 60 [2] 68 67 [2] 74 48 }

  condition:
    any of them
}