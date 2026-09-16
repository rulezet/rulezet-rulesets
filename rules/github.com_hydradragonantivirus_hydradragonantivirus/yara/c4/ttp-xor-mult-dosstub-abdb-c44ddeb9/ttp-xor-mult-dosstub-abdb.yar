rule TTP_XOR_MULT_DOSStub_abdb {
  strings:
    $key_abdb = { ff b3 [2] 8b ab [2] cc a9 [2] 8b b8 [2] c5 b4 [2] c9 be [2] de b5 [2] c5 fb [2] f8 }

  condition:
    any of them
}