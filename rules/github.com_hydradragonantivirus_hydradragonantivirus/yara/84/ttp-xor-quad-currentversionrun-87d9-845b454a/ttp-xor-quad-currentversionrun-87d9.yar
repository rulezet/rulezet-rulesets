rule TTP_XOR_QUAD_CurrentVersionRun_87d9 {
  strings:
    $key_87d9 = { d4 b6 [2] f0 b8 [2] db 94 [2] f5 b6 [2] e1 ad [2] ee b7 [2] f0 aa [2] f2 ab [2] e9 ad [2] f5 aa [2] e9 85 }

  condition:
    any of them
}