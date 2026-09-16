rule TTP_XOR_QUAD_CurrentVersionRun_4838 {
  strings:
    $key_4838 = { 1b 57 [2] 3f 59 [2] 14 75 [2] 3a 57 [2] 2e 4c [2] 21 56 [2] 3f 4b [2] 3d 4a [2] 26 4c [2] 3a 4b [2] 26 64 }

  condition:
    any of them
}