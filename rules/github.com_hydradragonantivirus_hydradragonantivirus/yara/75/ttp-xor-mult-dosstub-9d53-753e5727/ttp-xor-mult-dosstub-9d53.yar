rule TTP_XOR_MULT_DOSStub_9d53 {
  strings:
    $key_9d53 = { c9 3b [2] bd 23 [2] fa 21 [2] bd 30 [2] f3 3c [2] ff 36 [2] e8 3d [2] f3 73 [2] ce }

  condition:
    any of them
}