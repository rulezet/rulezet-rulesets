rule TTP_XOR_MULT_DOSStub_db3f {
  strings:
    $key_db3f = { 8f 57 [2] fb 4f [2] bc 4d [2] fb 5c [2] b5 50 [2] b9 5a [2] ae 51 [2] b5 1f [2] 88 }

  condition:
    any of them
}