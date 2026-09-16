rule TTP_XOR_MULT_DOSStub_dbf3 {
  strings:
    $key_dbf3 = { 8f 9b [2] fb 83 [2] bc 81 [2] fb 90 [2] b5 9c [2] b9 96 [2] ae 9d [2] b5 d3 [2] 88 }

  condition:
    any of them
}