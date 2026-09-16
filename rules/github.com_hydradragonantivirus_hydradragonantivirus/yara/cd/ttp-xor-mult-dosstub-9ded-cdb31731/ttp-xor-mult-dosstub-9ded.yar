rule TTP_XOR_MULT_DOSStub_9ded {
  strings:
    $key_9ded = { c9 85 [2] bd 9d [2] fa 9f [2] bd 8e [2] f3 82 [2] ff 88 [2] e8 83 [2] f3 cd [2] ce }

  condition:
    any of them
}