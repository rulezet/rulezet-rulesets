rule TTP_XOR_MULT_DOSStub_9de0 {
  strings:
    $key_9de0 = { c9 88 [2] bd 90 [2] fa 92 [2] bd 83 [2] f3 8f [2] ff 85 [2] e8 8e [2] f3 c0 [2] ce }

  condition:
    any of them
}