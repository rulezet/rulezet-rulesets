rule TTP_XOR_MULT_DOSStub_9f8c {
  strings:
    $key_9f8c = { cb e4 [2] bf fc [2] f8 fe [2] bf ef [2] f1 e3 [2] fd e9 [2] ea e2 [2] f1 ac [2] cc }

  condition:
    any of them
}