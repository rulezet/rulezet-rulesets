rule TTP_XOR_MULT_DOSStub_dbbd {
  strings:
    $key_dbbd = { 8f d5 [2] fb cd [2] bc cf [2] fb de [2] b5 d2 [2] b9 d8 [2] ae d3 [2] b5 9d [2] 88 }

  condition:
    any of them
}