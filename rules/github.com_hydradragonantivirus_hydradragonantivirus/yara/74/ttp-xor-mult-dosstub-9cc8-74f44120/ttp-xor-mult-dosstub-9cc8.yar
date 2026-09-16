rule TTP_XOR_MULT_DOSStub_9cc8 {
  strings:
    $key_9cc8 = { c8 a0 [2] bc b8 [2] fb ba [2] bc ab [2] f2 a7 [2] fe ad [2] e9 a6 [2] f2 e8 [2] cf }

  condition:
    any of them
}