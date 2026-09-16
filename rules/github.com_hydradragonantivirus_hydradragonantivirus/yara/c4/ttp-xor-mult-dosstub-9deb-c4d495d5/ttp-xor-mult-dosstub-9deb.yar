rule TTP_XOR_MULT_DOSStub_9deb {
  strings:
    $key_9deb = { c9 83 [2] bd 9b [2] fa 99 [2] bd 88 [2] f3 84 [2] ff 8e [2] e8 85 [2] f3 cb [2] ce }

  condition:
    any of them
}