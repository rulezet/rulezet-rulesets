rule TTP_XOR_MULT_DOSStub_dbfe {
  strings:
    $key_dbfe = { 8f 96 [2] fb 8e [2] bc 8c [2] fb 9d [2] b5 91 [2] b9 9b [2] ae 90 [2] b5 de [2] 88 }

  condition:
    any of them
}