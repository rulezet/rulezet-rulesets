rule TTP_XOR_MULT_DOSStub_db4f {
  strings:
    $key_db4f = { 8f 27 [2] fb 3f [2] bc 3d [2] fb 2c [2] b5 20 [2] b9 2a [2] ae 21 [2] b5 6f [2] 88 }

  condition:
    any of them
}