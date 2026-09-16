rule TTP_XOR_MULT_DOSStub_abcc {
  strings:
    $key_abcc = { ff a4 [2] 8b bc [2] cc be [2] 8b af [2] c5 a3 [2] c9 a9 [2] de a2 [2] c5 ec [2] f8 }

  condition:
    any of them
}