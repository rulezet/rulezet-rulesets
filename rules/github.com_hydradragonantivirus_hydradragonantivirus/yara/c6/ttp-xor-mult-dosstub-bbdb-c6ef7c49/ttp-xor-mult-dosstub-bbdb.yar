rule TTP_XOR_MULT_DOSStub_bbdb {
  strings:
    $key_bbdb = { ef b3 [2] 9b ab [2] dc a9 [2] 9b b8 [2] d5 b4 [2] d9 be [2] ce b5 [2] d5 fb [2] e8 }

  condition:
    any of them
}