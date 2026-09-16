rule TTP_XOR_QUAD_CurrentVersionRun_03fa {
  strings:
    $key_03fa = { 50 95 [2] 74 9b [2] 5f b7 [2] 71 95 [2] 65 8e [2] 6a 94 [2] 74 89 [2] 76 88 [2] 6d 8e [2] 71 89 [2] 6d a6 }

  condition:
    any of them
}