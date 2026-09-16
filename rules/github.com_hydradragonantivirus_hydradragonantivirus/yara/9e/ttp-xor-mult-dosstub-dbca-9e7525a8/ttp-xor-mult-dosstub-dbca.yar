rule TTP_XOR_MULT_DOSStub_dbca {
  strings:
    $key_dbca = { 8f a2 [2] fb ba [2] bc b8 [2] fb a9 [2] b5 a5 [2] b9 af [2] ae a4 [2] b5 ea [2] 88 }

  condition:
    any of them
}