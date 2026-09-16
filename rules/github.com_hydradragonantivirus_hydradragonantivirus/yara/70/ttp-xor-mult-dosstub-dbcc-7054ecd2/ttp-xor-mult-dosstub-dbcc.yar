rule TTP_XOR_MULT_DOSStub_dbcc {
  strings:
    $key_dbcc = { 8f a4 [2] fb bc [2] bc be [2] fb af [2] b5 a3 [2] b9 a9 [2] ae a2 [2] b5 ec [2] 88 }

  condition:
    any of them
}