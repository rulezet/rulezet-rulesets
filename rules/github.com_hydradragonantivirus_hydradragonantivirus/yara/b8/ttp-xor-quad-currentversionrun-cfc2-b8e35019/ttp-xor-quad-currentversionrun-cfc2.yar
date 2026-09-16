rule TTP_XOR_QUAD_CurrentVersionRun_cfc2 {
  strings:
    $key_cfc2 = { 9c ad [2] b8 a3 [2] 93 8f [2] bd ad [2] a9 b6 [2] a6 ac [2] b8 b1 [2] ba b0 [2] a1 b6 [2] bd b1 [2] a1 9e }

  condition:
    any of them
}