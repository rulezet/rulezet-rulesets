rule TTP_XOR_MULT_DOSStub_b993 {
  strings:
    $key_b993 = { ed fb [2] 99 e3 [2] de e1 [2] 99 f0 [2] d7 fc [2] db f6 [2] cc fd [2] d7 b3 [2] ea }

  condition:
    any of them
}