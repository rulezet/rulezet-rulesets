rule TTP_XOR_MULT_DOSStub_9db8 {
  strings:
    $key_9db8 = { c9 d0 [2] bd c8 [2] fa ca [2] bd db [2] f3 d7 [2] ff dd [2] e8 d6 [2] f3 98 [2] ce }

  condition:
    any of them
}