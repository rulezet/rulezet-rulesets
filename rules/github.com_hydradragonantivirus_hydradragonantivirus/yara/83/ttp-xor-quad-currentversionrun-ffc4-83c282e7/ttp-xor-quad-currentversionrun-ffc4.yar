rule TTP_XOR_QUAD_CurrentVersionRun_ffc4 {
  strings:
    $key_ffc4 = { ac ab [2] 88 a5 [2] a3 89 [2] 8d ab [2] 99 b0 [2] 96 aa [2] 88 b7 [2] 8a b6 [2] 91 b0 [2] 8d b7 [2] 91 98 }

  condition:
    any of them
}