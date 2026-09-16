rule TTP_XOR_MULT_DOSStub_9d73 {
  strings:
    $key_9d73 = { c9 1b [2] bd 03 [2] fa 01 [2] bd 10 [2] f3 1c [2] ff 16 [2] e8 1d [2] f3 53 [2] ce }

  condition:
    any of them
}