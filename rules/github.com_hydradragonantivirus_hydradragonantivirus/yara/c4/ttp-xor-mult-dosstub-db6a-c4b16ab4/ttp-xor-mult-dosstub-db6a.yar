rule TTP_XOR_MULT_DOSStub_db6a {
  strings:
    $key_db6a = { 8f 02 [2] fb 1a [2] bc 18 [2] fb 09 [2] b5 05 [2] b9 0f [2] ae 04 [2] b5 4a [2] 88 }

  condition:
    any of them
}