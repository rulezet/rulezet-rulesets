rule TTP_XOR_MULT_DOSStub_db04 {
  strings:
    $key_db04 = { 8f 6c [2] fb 74 [2] bc 76 [2] fb 67 [2] b5 6b [2] b9 61 [2] ae 6a [2] b5 24 [2] 88 }

  condition:
    any of them
}