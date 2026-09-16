rule TTP_XOR_QUAD_CurrentVersionRun_03e9 {
  strings:
    $key_03e9 = { 50 86 [2] 74 88 [2] 5f a4 [2] 71 86 [2] 65 9d [2] 6a 87 [2] 74 9a [2] 76 9b [2] 6d 9d [2] 71 9a [2] 6d b5 }

  condition:
    any of them
}