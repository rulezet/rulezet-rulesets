rule TTP_XOR_MULT_DOSStub_eadb {
  strings:
    $key_eadb = { be b3 [2] ca ab [2] 8d a9 [2] ca b8 [2] 84 b4 [2] 88 be [2] 9f b5 [2] 84 fb [2] b9 }

  condition:
    any of them
}