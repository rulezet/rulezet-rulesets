rule TTP_XOR_QUAD_CurrentVersionRun_99df {
  strings:
    $key_99df = { ca b0 [2] ee be [2] c5 92 [2] eb b0 [2] ff ab [2] f0 b1 [2] ee ac [2] ec ad [2] f7 ab [2] eb ac [2] f7 83 }

  condition:
    any of them
}