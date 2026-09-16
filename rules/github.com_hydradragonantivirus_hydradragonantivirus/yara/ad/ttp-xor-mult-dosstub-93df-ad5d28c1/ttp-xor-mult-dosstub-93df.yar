rule TTP_XOR_MULT_DOSStub_93df {
  strings:
    $key_93df = { c7 b7 [2] b3 af [2] f4 ad [2] b3 bc [2] fd b0 [2] f1 ba [2] e6 b1 [2] fd ff [2] c0 }

  condition:
    any of them
}