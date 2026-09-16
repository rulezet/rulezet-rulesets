rule TTP_XOR_MULT_DOSStub_9d10 {
  strings:
    $key_9d10 = { c9 78 [2] bd 60 [2] fa 62 [2] bd 73 [2] f3 7f [2] ff 75 [2] e8 7e [2] f3 30 [2] ce }

  condition:
    any of them
}