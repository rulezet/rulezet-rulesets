rule TTP_XOR_MULT_DOSStub_3988 {
  strings:
    $key_3988 = { 6d e0 [2] 19 f8 [2] 5e fa [2] 19 eb [2] 57 e7 [2] 5b ed [2] 4c e6 [2] 57 a8 [2] 6a }

  condition:
    any of them
}