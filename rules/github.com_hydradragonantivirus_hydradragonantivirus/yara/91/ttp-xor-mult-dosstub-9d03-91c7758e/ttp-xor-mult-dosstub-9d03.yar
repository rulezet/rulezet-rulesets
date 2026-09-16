rule TTP_XOR_MULT_DOSStub_9d03 {
  strings:
    $key_9d03 = { c9 6b [2] bd 73 [2] fa 71 [2] bd 60 [2] f3 6c [2] ff 66 [2] e8 6d [2] f3 23 [2] ce }

  condition:
    any of them
}