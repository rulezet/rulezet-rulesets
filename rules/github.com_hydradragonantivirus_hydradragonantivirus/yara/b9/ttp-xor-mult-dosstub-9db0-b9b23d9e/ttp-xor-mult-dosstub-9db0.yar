rule TTP_XOR_MULT_DOSStub_9db0 {
  strings:
    $key_9db0 = { c9 d8 [2] bd c0 [2] fa c2 [2] bd d3 [2] f3 df [2] ff d5 [2] e8 de [2] f3 90 [2] ce }

  condition:
    any of them
}