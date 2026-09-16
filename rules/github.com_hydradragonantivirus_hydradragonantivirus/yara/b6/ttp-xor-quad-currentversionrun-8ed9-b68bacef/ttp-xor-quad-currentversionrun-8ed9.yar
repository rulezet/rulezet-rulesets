rule TTP_XOR_QUAD_CurrentVersionRun_8ed9 {
  strings:
    $key_8ed9 = { dd b6 [2] f9 b8 [2] d2 94 [2] fc b6 [2] e8 ad [2] e7 b7 [2] f9 aa [2] fb ab [2] e0 ad [2] fc aa [2] e0 85 }

  condition:
    any of them
}