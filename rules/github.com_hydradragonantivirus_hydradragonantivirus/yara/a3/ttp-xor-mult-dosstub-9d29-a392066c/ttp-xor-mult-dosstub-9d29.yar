rule TTP_XOR_MULT_DOSStub_9d29 {
  strings:
    $key_9d29 = { c9 41 [2] bd 59 [2] fa 5b [2] bd 4a [2] f3 46 [2] ff 4c [2] e8 47 [2] f3 09 [2] ce }

  condition:
    any of them
}