rule TTP_XOR_MULT_DOSStub_9dcd {
  strings:
    $key_9dcd = { c9 a5 [2] bd bd [2] fa bf [2] bd ae [2] f3 a2 [2] ff a8 [2] e8 a3 [2] f3 ed [2] ce }

  condition:
    any of them
}