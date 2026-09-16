rule TTP_XOR_MULT_DOSStub_dbcd {
  strings:
    $key_dbcd = { 8f a5 [2] fb bd [2] bc bf [2] fb ae [2] b5 a2 [2] b9 a8 [2] ae a3 [2] b5 ed [2] 88 }

  condition:
    any of them
}