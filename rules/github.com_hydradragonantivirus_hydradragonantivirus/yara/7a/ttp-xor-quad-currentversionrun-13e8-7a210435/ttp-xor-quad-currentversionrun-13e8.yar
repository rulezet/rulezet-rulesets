rule TTP_XOR_QUAD_CurrentVersionRun_13e8 {
  strings:
    $key_13e8 = { 40 87 [2] 64 89 [2] 4f a5 [2] 61 87 [2] 75 9c [2] 7a 86 [2] 64 9b [2] 66 9a [2] 7d 9c [2] 61 9b [2] 7d b4 }

  condition:
    any of them
}