rule TTP_XOR_MULT_DOSStub_9d13 {
  strings:
    $key_9d13 = { c9 7b [2] bd 63 [2] fa 61 [2] bd 70 [2] f3 7c [2] ff 76 [2] e8 7d [2] f3 33 [2] ce }

  condition:
    any of them
}