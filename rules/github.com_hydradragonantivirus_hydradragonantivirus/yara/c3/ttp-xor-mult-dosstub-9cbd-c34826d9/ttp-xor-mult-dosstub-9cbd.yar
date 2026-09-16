rule TTP_XOR_MULT_DOSStub_9cbd {
  strings:
    $key_9cbd = { c8 d5 [2] bc cd [2] fb cf [2] bc de [2] f2 d2 [2] fe d8 [2] e9 d3 [2] f2 9d [2] cf }

  condition:
    any of them
}