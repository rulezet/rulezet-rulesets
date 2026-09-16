rule TTP_XOR_MULT_DOSStub_dbbf {
  strings:
    $key_dbbf = { 8f d7 [2] fb cf [2] bc cd [2] fb dc [2] b5 d0 [2] b9 da [2] ae d1 [2] b5 9f [2] 88 }

  condition:
    any of them
}