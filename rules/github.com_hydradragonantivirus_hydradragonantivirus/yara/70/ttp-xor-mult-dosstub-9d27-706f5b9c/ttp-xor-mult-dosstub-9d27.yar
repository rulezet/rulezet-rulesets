rule TTP_XOR_MULT_DOSStub_9d27 {
  strings:
    $key_9d27 = { c9 4f [2] bd 57 [2] fa 55 [2] bd 44 [2] f3 48 [2] ff 42 [2] e8 49 [2] f3 07 [2] ce }

  condition:
    any of them
}