rule TTP_XOR_MULT_DOSStub_db0d {
  strings:
    $key_db0d = { 8f 65 [2] fb 7d [2] bc 7f [2] fb 6e [2] b5 62 [2] b9 68 [2] ae 63 [2] b5 2d [2] 88 }

  condition:
    any of them
}