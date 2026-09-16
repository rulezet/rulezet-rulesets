rule TTP_XOR_MULT_DOSStub_dbe6 {
  strings:
    $key_dbe6 = { 8f 8e [2] fb 96 [2] bc 94 [2] fb 85 [2] b5 89 [2] b9 83 [2] ae 88 [2] b5 c6 [2] 88 }

  condition:
    any of them
}