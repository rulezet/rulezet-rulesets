rule TTP_XOR_MULT_DOSStub_9aa3 {
  strings:
    $key_9aa3 = { ce cb [2] ba d3 [2] fd d1 [2] ba c0 [2] f4 cc [2] f8 c6 [2] ef cd [2] f4 83 [2] c9 }

  condition:
    any of them
}