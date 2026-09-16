rule TTP_XOR_MULT_DOSStub_aedb {
  strings:
    $key_aedb = { fa b3 [2] 8e ab [2] c9 a9 [2] 8e b8 [2] c0 b4 [2] cc be [2] db b5 [2] c0 fb [2] fd }

  condition:
    any of them
}