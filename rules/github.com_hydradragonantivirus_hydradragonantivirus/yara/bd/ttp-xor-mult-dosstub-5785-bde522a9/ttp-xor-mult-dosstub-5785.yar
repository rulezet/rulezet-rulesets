rule TTP_XOR_MULT_DOSStub_5785 {
  strings:
    $key_5785 = { 03 ed [2] 77 f5 [2] 30 f7 [2] 77 e6 [2] 39 ea [2] 35 e0 [2] 22 eb [2] 39 a5 [2] 04 }

  condition:
    any of them
}