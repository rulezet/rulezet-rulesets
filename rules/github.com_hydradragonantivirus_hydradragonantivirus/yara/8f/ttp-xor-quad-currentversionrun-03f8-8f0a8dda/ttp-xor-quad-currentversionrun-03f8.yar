rule TTP_XOR_QUAD_CurrentVersionRun_03f8 {
  strings:
    $key_03f8 = { 50 97 [2] 74 99 [2] 5f b5 [2] 71 97 [2] 65 8c [2] 6a 96 [2] 74 8b [2] 76 8a [2] 6d 8c [2] 71 8b [2] 6d a4 }

  condition:
    any of them
}