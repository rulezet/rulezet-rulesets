rule TTP_XOR_MULT_DOSStub_9db5 {
  strings:
    $key_9db5 = { c9 dd [2] bd c5 [2] fa c7 [2] bd d6 [2] f3 da [2] ff d0 [2] e8 db [2] f3 95 [2] ce }

  condition:
    any of them
}