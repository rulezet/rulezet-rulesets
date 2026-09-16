rule TTP_XOR_MULT_DOSStub_db6d {
  strings:
    $key_db6d = { 8f 05 [2] fb 1d [2] bc 1f [2] fb 0e [2] b5 02 [2] b9 08 [2] ae 03 [2] b5 4d [2] 88 }

  condition:
    any of them
}