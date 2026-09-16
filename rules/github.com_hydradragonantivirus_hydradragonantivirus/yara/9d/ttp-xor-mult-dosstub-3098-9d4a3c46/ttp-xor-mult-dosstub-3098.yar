rule TTP_XOR_MULT_DOSStub_3098 {
  strings:
    $key_3098 = { 64 f0 [2] 10 e8 [2] 57 ea [2] 10 fb [2] 5e f7 [2] 52 fd [2] 45 f6 [2] 5e b8 [2] 63 }

  condition:
    any of them
}