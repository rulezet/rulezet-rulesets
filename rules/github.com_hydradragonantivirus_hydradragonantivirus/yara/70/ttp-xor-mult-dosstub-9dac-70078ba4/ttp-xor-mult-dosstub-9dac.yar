rule TTP_XOR_MULT_DOSStub_9dac {
  strings:
    $key_9dac = { c9 c4 [2] bd dc [2] fa de [2] bd cf [2] f3 c3 [2] ff c9 [2] e8 c2 [2] f3 8c [2] ce }

  condition:
    any of them
}