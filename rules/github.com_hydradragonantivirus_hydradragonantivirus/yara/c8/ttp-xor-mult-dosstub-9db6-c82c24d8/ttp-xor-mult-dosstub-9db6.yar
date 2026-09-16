rule TTP_XOR_MULT_DOSStub_9db6 {
  strings:
    $key_9db6 = { c9 de [2] bd c6 [2] fa c4 [2] bd d5 [2] f3 d9 [2] ff d3 [2] e8 d8 [2] f3 96 [2] ce }

  condition:
    any of them
}