rule TTP_XOR_MULT_DOSStub_db23 {
  strings:
    $key_db23 = { 8f 4b [2] fb 53 [2] bc 51 [2] fb 40 [2] b5 4c [2] b9 46 [2] ae 4d [2] b5 03 [2] 88 }

  condition:
    any of them
}