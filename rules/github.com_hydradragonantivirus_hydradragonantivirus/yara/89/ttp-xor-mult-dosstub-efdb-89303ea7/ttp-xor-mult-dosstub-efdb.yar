rule TTP_XOR_MULT_DOSStub_efdb {
  strings:
    $key_efdb = { bb b3 [2] cf ab [2] 88 a9 [2] cf b8 [2] 81 b4 [2] 8d be [2] 9a b5 [2] 81 fb [2] bc }

  condition:
    any of them
}