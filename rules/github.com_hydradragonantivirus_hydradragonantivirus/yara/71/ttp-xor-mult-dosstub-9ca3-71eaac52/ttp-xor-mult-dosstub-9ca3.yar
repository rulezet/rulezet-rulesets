rule TTP_XOR_MULT_DOSStub_9ca3 {
  strings:
    $key_9ca3 = { c8 cb [2] bc d3 [2] fb d1 [2] bc c0 [2] f2 cc [2] fe c6 [2] e9 cd [2] f2 83 [2] cf }

  condition:
    any of them
}