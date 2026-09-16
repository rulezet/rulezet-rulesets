rule TTP_XOR_MULT_DOSStub_9d50 {
  strings:
    $key_9d50 = { c9 38 [2] bd 20 [2] fa 22 [2] bd 33 [2] f3 3f [2] ff 35 [2] e8 3e [2] f3 70 [2] ce }

  condition:
    any of them
}