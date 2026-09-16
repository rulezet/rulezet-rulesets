rule TTP_XOR_MULT_DOSStub_9d35 {
  strings:
    $key_9d35 = { c9 5d [2] bd 45 [2] fa 47 [2] bd 56 [2] f3 5a [2] ff 50 [2] e8 5b [2] f3 15 [2] ce }

  condition:
    any of them
}