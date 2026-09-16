rule TTP_XOR_MULT_DOSStub_db2e {
  strings:
    $key_db2e = { 8f 46 [2] fb 5e [2] bc 5c [2] fb 4d [2] b5 41 [2] b9 4b [2] ae 40 [2] b5 0e [2] 88 }

  condition:
    any of them
}