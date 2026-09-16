rule TTP_XOR_MULT_DOSStub_93dd {
  strings:
    $key_93dd = { c7 b5 [2] b3 ad [2] f4 af [2] b3 be [2] fd b2 [2] f1 b8 [2] e6 b3 [2] fd fd [2] c0 }

  condition:
    any of them
}