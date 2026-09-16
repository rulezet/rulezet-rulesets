rule TTP_XOR_MULT_DOSStub_82de {
  strings:
    $key_82de = { d6 b6 [2] a2 ae [2] e5 ac [2] a2 bd [2] ec b1 [2] e0 bb [2] f7 b0 [2] ec fe [2] d1 }

  condition:
    any of them
}