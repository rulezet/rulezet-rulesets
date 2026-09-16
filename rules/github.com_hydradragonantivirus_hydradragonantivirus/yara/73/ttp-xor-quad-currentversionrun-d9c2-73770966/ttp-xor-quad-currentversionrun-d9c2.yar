rule TTP_XOR_QUAD_CurrentVersionRun_d9c2 {
  strings:
    $key_d9c2 = { 8a ad [2] ae a3 [2] 85 8f [2] ab ad [2] bf b6 [2] b0 ac [2] ae b1 [2] ac b0 [2] b7 b6 [2] ab b1 [2] b7 9e }

  condition:
    any of them
}