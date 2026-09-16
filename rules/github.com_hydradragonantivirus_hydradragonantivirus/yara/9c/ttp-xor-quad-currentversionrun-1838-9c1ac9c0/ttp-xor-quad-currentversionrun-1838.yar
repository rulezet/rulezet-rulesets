rule TTP_XOR_QUAD_CurrentVersionRun_1838 {
  strings:
    $key_1838 = { 4b 57 [2] 6f 59 [2] 44 75 [2] 6a 57 [2] 7e 4c [2] 71 56 [2] 6f 4b [2] 6d 4a [2] 76 4c [2] 6a 4b [2] 76 64 }

  condition:
    any of them
}