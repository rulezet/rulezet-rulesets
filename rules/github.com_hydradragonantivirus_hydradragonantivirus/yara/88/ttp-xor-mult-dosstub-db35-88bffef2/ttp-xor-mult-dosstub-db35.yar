rule TTP_XOR_MULT_DOSStub_db35 {
  strings:
    $key_db35 = { 8f 5d [2] fb 45 [2] bc 47 [2] fb 56 [2] b5 5a [2] b9 50 [2] ae 5b [2] b5 15 [2] 88 }

  condition:
    any of them
}