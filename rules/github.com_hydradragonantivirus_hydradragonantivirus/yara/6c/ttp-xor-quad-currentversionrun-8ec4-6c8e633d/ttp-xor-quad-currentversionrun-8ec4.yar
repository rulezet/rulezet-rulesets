rule TTP_XOR_QUAD_CurrentVersionRun_8ec4 {
  strings:
    $key_8ec4 = { dd ab [2] f9 a5 [2] d2 89 [2] fc ab [2] e8 b0 [2] e7 aa [2] f9 b7 [2] fb b6 [2] e0 b0 [2] fc b7 [2] e0 98 }

  condition:
    any of them
}