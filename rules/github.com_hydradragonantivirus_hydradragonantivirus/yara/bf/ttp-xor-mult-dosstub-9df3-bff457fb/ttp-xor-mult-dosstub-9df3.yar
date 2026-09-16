rule TTP_XOR_MULT_DOSStub_9df3 {
  strings:
    $key_9df3 = { c9 9b [2] bd 83 [2] fa 81 [2] bd 90 [2] f3 9c [2] ff 96 [2] e8 9d [2] f3 d3 [2] ce }

  condition:
    any of them
}