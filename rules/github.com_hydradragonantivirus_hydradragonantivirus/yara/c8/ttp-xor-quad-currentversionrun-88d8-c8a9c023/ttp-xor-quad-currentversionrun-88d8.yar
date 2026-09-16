rule TTP_XOR_QUAD_CurrentVersionRun_88d8 {
  strings:
    $key_88d8 = { db b7 [2] ff b9 [2] d4 95 [2] fa b7 [2] ee ac [2] e1 b6 [2] ff ab [2] fd aa [2] e6 ac [2] fa ab [2] e6 84 }

  condition:
    any of them
}