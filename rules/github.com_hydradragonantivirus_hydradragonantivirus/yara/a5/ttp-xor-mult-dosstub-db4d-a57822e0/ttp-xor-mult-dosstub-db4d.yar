rule TTP_XOR_MULT_DOSStub_db4d {
  strings:
    $key_db4d = { 8f 25 [2] fb 3d [2] bc 3f [2] fb 2e [2] b5 22 [2] b9 28 [2] ae 23 [2] b5 6d [2] 88 }

  condition:
    any of them
}