rule TTP_XOR_MULT_DOSStub_658b {
  strings:
    $key_658b = { 31 e3 [2] 45 fb [2] 02 f9 [2] 45 e8 [2] 0b e4 [2] 07 ee [2] 10 e5 [2] 0b ab [2] 36 }

  condition:
    any of them
}