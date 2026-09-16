rule TTP_XOR_QUAD_CurrentVersionRun_8adf {
  strings:
    $key_8adf = { d9 b0 [2] fd be [2] d6 92 [2] f8 b0 [2] ec ab [2] e3 b1 [2] fd ac [2] ff ad [2] e4 ab [2] f8 ac [2] e4 83 }

  condition:
    any of them
}