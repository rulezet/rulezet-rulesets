rule TTP_XOR_MULT_DOSStub_9dad {
  strings:
    $key_9dad = { c9 c5 [2] bd dd [2] fa df [2] bd ce [2] f3 c2 [2] ff c8 [2] e8 c3 [2] f3 8d [2] ce }

  condition:
    any of them
}