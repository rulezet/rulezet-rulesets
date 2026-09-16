rule TTP_XOR_MULT_DOSStub_db7b {
  strings:
    $key_db7b = { 8f 13 [2] fb 0b [2] bc 09 [2] fb 18 [2] b5 14 [2] b9 1e [2] ae 15 [2] b5 5b [2] 88 }

  condition:
    any of them
}