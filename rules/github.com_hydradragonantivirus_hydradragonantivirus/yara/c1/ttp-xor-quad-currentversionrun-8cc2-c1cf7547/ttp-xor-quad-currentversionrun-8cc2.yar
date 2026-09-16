rule TTP_XOR_QUAD_CurrentVersionRun_8cc2 {
  strings:
    $key_8cc2 = { df ad [2] fb a3 [2] d0 8f [2] fe ad [2] ea b6 [2] e5 ac [2] fb b1 [2] f9 b0 [2] e2 b6 [2] fe b1 [2] e2 9e }

  condition:
    any of them
}