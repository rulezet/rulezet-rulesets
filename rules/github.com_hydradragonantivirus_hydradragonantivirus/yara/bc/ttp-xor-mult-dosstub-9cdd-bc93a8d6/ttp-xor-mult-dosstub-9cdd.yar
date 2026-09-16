rule TTP_XOR_MULT_DOSStub_9cdd {
  strings:
    $key_9cdd = { c8 b5 [2] bc ad [2] fb af [2] bc be [2] f2 b2 [2] fe b8 [2] e9 b3 [2] f2 fd [2] cf }

  condition:
    any of them
}