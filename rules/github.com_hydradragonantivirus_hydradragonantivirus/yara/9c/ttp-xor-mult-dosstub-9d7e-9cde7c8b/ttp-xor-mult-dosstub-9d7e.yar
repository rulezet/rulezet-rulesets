rule TTP_XOR_MULT_DOSStub_9d7e {
  strings:
    $key_9d7e = { c9 16 [2] bd 0e [2] fa 0c [2] bd 1d [2] f3 11 [2] ff 1b [2] e8 10 [2] f3 5e [2] ce }

  condition:
    any of them
}