rule TTP_XOR_MULT_DOSStub_dbaf {
  strings:
    $key_dbaf = { 8f c7 [2] fb df [2] bc dd [2] fb cc [2] b5 c0 [2] b9 ca [2] ae c1 [2] b5 8f [2] 88 }

  condition:
    any of them
}