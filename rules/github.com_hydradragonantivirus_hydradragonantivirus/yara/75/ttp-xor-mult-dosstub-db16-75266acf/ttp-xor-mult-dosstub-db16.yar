rule TTP_XOR_MULT_DOSStub_db16 {
  strings:
    $key_db16 = { 8f 7e [2] fb 66 [2] bc 64 [2] fb 75 [2] b5 79 [2] b9 73 [2] ae 78 [2] b5 36 [2] 88 }

  condition:
    any of them
}