rule TTP_XOR_MULT_DOSStub_9dfe {
  strings:
    $key_9dfe = { c9 96 [2] bd 8e [2] fa 8c [2] bd 9d [2] f3 91 [2] ff 9b [2] e8 90 [2] f3 de [2] ce }

  condition:
    any of them
}