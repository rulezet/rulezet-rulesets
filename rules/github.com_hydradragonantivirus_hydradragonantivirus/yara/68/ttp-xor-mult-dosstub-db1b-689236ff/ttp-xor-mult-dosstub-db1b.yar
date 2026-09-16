rule TTP_XOR_MULT_DOSStub_db1b {
  strings:
    $key_db1b = { 8f 73 [2] fb 6b [2] bc 69 [2] fb 78 [2] b5 74 [2] b9 7e [2] ae 75 [2] b5 3b [2] 88 }

  condition:
    any of them
}