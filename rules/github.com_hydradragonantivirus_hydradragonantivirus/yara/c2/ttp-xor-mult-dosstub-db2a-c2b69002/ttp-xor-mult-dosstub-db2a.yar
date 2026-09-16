rule TTP_XOR_MULT_DOSStub_db2a {
  strings:
    $key_db2a = { 8f 42 [2] fb 5a [2] bc 58 [2] fb 49 [2] b5 45 [2] b9 4f [2] ae 44 [2] b5 0a [2] 88 }

  condition:
    any of them
}