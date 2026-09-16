rule TTP_XOR_MULT_DOSStub_9db3 {
  strings:
    $key_9db3 = { c9 db [2] bd c3 [2] fa c1 [2] bd d0 [2] f3 dc [2] ff d6 [2] e8 dd [2] f3 93 [2] ce }

  condition:
    any of them
}