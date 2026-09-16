rule TTP_XOR_MULT_DOSStub_9ddb {
  strings:
    $key_9ddb = { c9 b3 [2] bd ab [2] fa a9 [2] bd b8 [2] f3 b4 [2] ff be [2] e8 b5 [2] f3 fb [2] ce }

  condition:
    any of them
}