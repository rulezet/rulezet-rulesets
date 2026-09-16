rule TTP_XOR_MULT_DOSStub_1988 {
  strings:
    $key_1988 = { 4d e0 [2] 39 f8 [2] 7e fa [2] 39 eb [2] 77 e7 [2] 7b ed [2] 6c e6 [2] 77 a8 [2] 4a }

  condition:
    any of them
}