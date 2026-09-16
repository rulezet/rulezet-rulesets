rule TTP_XOR_MULT_DOSStub_9593 {
  strings:
    $key_9593 = { c1 fb [2] b5 e3 [2] f2 e1 [2] b5 f0 [2] fb fc [2] f7 f6 [2] e0 fd [2] fb b3 [2] c6 }

  condition:
    any of them
}