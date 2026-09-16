rule TTP_XOR_QUAD_CurrentVersionRun_3838 {
  strings:
    $key_3838 = { 6b 57 [2] 4f 59 [2] 64 75 [2] 4a 57 [2] 5e 4c [2] 51 56 [2] 4f 4b [2] 4d 4a [2] 56 4c [2] 4a 4b [2] 56 64 }

  condition:
    any of them
}