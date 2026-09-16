rule TTP_XOR_MULT_DOSStub_9d3d {
  strings:
    $key_9d3d = { c9 55 [2] bd 4d [2] fa 4f [2] bd 5e [2] f3 52 [2] ff 58 [2] e8 53 [2] f3 1d [2] ce }

  condition:
    any of them
}