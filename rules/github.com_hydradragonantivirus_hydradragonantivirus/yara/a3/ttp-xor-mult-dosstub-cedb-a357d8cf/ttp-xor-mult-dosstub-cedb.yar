rule TTP_XOR_MULT_DOSStub_cedb {
  strings:
    $key_cedb = { 9a b3 [2] ee ab [2] a9 a9 [2] ee b8 [2] a0 b4 [2] ac be [2] bb b5 [2] a0 fb [2] 9d }

  condition:
    any of them
}