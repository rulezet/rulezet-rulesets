rule TTP_XOR_MULT_DOSStub_348b {
  strings:
    $key_348b = { 60 e3 [2] 14 fb [2] 53 f9 [2] 14 e8 [2] 5a e4 [2] 56 ee [2] 41 e5 [2] 5a ab [2] 67 }

  condition:
    any of them
}