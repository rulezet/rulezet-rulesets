rule TTP_XOR_MULT_DOSStub_9dfd {
  strings:
    $key_9dfd = { c9 95 [2] bd 8d [2] fa 8f [2] bd 9e [2] f3 92 [2] ff 98 [2] e8 93 [2] f3 dd [2] ce }

  condition:
    any of them
}