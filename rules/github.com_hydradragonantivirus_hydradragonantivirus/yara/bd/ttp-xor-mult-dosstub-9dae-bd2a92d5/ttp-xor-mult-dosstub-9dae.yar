rule TTP_XOR_MULT_DOSStub_9dae {
  strings:
    $key_9dae = { c9 c6 [2] bd de [2] fa dc [2] bd cd [2] f3 c1 [2] ff cb [2] e8 c0 [2] f3 8e [2] ce }

  condition:
    any of them
}