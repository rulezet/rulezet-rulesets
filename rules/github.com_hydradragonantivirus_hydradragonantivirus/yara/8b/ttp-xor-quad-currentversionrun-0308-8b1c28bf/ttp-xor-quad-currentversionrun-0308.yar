rule TTP_XOR_QUAD_CurrentVersionRun_0308 {
  strings:
    $key_0308 = { 50 67 [2] 74 69 [2] 5f 45 [2] 71 67 [2] 65 7c [2] 6a 66 [2] 74 7b [2] 76 7a [2] 6d 7c [2] 71 7b [2] 6d 54 }

  condition:
    any of them
}