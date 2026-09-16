rule TTP_XOR_MULT_DOSStub_db7f {
  strings:
    $key_db7f = { 8f 17 [2] fb 0f [2] bc 0d [2] fb 1c [2] b5 10 [2] b9 1a [2] ae 11 [2] b5 5f [2] 88 }

  condition:
    any of them
}