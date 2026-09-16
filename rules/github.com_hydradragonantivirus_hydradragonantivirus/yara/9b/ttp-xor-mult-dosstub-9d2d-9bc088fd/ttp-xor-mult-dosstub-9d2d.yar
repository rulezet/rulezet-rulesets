rule TTP_XOR_MULT_DOSStub_9d2d {
  strings:
    $key_9d2d = { c9 45 [2] bd 5d [2] fa 5f [2] bd 4e [2] f3 42 [2] ff 48 [2] e8 43 [2] f3 0d [2] ce }

  condition:
    any of them
}