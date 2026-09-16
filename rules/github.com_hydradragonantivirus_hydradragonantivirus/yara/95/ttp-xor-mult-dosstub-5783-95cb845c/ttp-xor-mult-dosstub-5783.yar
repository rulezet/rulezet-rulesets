rule TTP_XOR_MULT_DOSStub_5783 {
  strings:
    $key_5783 = { 03 eb [2] 77 f3 [2] 30 f1 [2] 77 e0 [2] 39 ec [2] 35 e6 [2] 22 ed [2] 39 a3 [2] 04 }

  condition:
    any of them
}