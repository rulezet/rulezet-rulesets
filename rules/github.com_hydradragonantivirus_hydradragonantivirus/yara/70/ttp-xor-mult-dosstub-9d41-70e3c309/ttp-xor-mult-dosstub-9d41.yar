rule TTP_XOR_MULT_DOSStub_9d41 {
  strings:
    $key_9d41 = { c9 29 [2] bd 31 [2] fa 33 [2] bd 22 [2] f3 2e [2] ff 24 [2] e8 2f [2] f3 61 [2] ce }

  condition:
    any of them
}