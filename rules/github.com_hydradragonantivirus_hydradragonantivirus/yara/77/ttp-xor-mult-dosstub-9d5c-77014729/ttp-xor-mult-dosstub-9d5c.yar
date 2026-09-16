rule TTP_XOR_MULT_DOSStub_9d5c {
  strings:
    $key_9d5c = { c9 34 [2] bd 2c [2] fa 2e [2] bd 3f [2] f3 33 [2] ff 39 [2] e8 32 [2] f3 7c [2] ce }

  condition:
    any of them
}