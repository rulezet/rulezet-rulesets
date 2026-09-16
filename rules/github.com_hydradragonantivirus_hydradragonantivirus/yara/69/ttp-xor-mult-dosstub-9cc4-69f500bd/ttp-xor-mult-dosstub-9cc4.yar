rule TTP_XOR_MULT_DOSStub_9cc4 {
  strings:
    $key_9cc4 = { c8 ac [2] bc b4 [2] fb b6 [2] bc a7 [2] f2 ab [2] fe a1 [2] e9 aa [2] f2 e4 [2] cf }

  condition:
    any of them
}