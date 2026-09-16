rule TTP_XOR_MULT_DOSStub_659e {
  strings:
    $key_659e = { 31 f6 [2] 45 ee [2] 02 ec [2] 45 fd [2] 0b f1 [2] 07 fb [2] 10 f0 [2] 0b be [2] 36 }

  condition:
    any of them
}