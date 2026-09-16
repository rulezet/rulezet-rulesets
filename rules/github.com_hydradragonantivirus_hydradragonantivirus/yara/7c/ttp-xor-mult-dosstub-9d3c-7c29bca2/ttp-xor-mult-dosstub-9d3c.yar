rule TTP_XOR_MULT_DOSStub_9d3c {
  strings:
    $key_9d3c = { c9 54 [2] bd 4c [2] fa 4e [2] bd 5f [2] f3 53 [2] ff 59 [2] e8 52 [2] f3 1c [2] ce }

  condition:
    any of them
}