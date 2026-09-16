rule TTP_XOR_MULT_DOSStub_db6e {
  strings:
    $key_db6e = { 8f 06 [2] fb 1e [2] bc 1c [2] fb 0d [2] b5 01 [2] b9 0b [2] ae 00 [2] b5 4e [2] 88 }

  condition:
    any of them
}