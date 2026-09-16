rule TTP_XOR_MULT_DOSStub_dbae {
  strings:
    $key_dbae = { 8f c6 [2] fb de [2] bc dc [2] fb cd [2] b5 c1 [2] b9 cb [2] ae c0 [2] b5 8e [2] 88 }

  condition:
    any of them
}