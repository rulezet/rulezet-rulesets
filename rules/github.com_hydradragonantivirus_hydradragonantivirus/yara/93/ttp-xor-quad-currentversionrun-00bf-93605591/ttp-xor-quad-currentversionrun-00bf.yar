rule TTP_XOR_QUAD_CurrentVersionRun_00bf {
  strings:
    $key_00bf = { 53 d0 [2] 77 de [2] 5c f2 [2] 72 d0 [2] 66 cb [2] 69 d1 [2] 77 cc [2] 75 cd [2] 6e cb [2] 72 cc [2] 6e e3 }

  condition:
    any of them
}