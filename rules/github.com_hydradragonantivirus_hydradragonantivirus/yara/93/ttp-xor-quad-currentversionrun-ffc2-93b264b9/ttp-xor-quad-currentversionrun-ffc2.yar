rule TTP_XOR_QUAD_CurrentVersionRun_ffc2 {
  strings:
    $key_ffc2 = { ac ad [2] 88 a3 [2] a3 8f [2] 8d ad [2] 99 b6 [2] 96 ac [2] 88 b1 [2] 8a b0 [2] 91 b6 [2] 8d b1 [2] 91 9e }

  condition:
    any of them
}