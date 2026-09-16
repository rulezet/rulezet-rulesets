rule TTP_XOR_QUAD_CurrentVersionRun_5138 {
  strings:
    $key_5138 = { 02 57 [2] 26 59 [2] 0d 75 [2] 23 57 [2] 37 4c [2] 38 56 [2] 26 4b [2] 24 4a [2] 3f 4c [2] 23 4b [2] 3f 64 }

  condition:
    any of them
}