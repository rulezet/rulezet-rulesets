rule TTP_XOR_MULT_DOSStub_9db4 {
  strings:
    $key_9db4 = { c9 dc [2] bd c4 [2] fa c6 [2] bd d7 [2] f3 db [2] ff d1 [2] e8 da [2] f3 94 [2] ce }

  condition:
    any of them
}