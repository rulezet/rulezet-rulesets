rule TTP_XOR_MULT_DOSStub_9d8e {
  strings:
    $key_9d8e = { c9 e6 [2] bd fe [2] fa fc [2] bd ed [2] f3 e1 [2] ff eb [2] e8 e0 [2] f3 ae [2] ce }

  condition:
    any of them
}