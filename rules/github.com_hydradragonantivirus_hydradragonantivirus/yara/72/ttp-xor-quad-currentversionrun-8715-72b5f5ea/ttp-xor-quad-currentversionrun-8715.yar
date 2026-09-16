rule TTP_XOR_QUAD_CurrentVersionRun_8715 {
  strings:
    $key_8715 = { d4 7a [2] f0 74 [2] db 58 [2] f5 7a [2] e1 61 [2] ee 7b [2] f0 66 [2] f2 67 [2] e9 61 [2] f5 66 [2] e9 49 }

  condition:
    any of them
}