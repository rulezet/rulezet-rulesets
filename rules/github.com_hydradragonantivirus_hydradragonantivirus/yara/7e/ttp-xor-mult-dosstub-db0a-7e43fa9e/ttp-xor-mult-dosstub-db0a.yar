rule TTP_XOR_MULT_DOSStub_db0a {
  strings:
    $key_db0a = { 8f 62 [2] fb 7a [2] bc 78 [2] fb 69 [2] b5 65 [2] b9 6f [2] ae 64 [2] b5 2a [2] 88 }

  condition:
    any of them
}