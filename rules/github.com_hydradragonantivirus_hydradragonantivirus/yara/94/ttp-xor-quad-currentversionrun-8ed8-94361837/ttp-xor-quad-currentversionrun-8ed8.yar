rule TTP_XOR_QUAD_CurrentVersionRun_8ed8 {
  strings:
    $key_8ed8 = { dd b7 [2] f9 b9 [2] d2 95 [2] fc b7 [2] e8 ac [2] e7 b6 [2] f9 ab [2] fb aa [2] e0 ac [2] fc ab [2] e0 84 }

  condition:
    any of them
}