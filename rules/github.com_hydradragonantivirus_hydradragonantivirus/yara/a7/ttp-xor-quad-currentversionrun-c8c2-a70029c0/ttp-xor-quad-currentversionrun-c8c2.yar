rule TTP_XOR_QUAD_CurrentVersionRun_c8c2 {
  strings:
    $key_c8c2 = { 9b ad [2] bf a3 [2] 94 8f [2] ba ad [2] ae b6 [2] a1 ac [2] bf b1 [2] bd b0 [2] a6 b6 [2] ba b1 [2] a6 9e }

  condition:
    any of them
}