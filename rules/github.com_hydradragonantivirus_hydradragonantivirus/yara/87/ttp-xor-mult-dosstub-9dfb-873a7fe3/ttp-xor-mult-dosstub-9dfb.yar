rule TTP_XOR_MULT_DOSStub_9dfb {
  strings:
    $key_9dfb = { c9 93 [2] bd 8b [2] fa 89 [2] bd 98 [2] f3 94 [2] ff 9e [2] e8 95 [2] f3 db [2] ce }

  condition:
    any of them
}