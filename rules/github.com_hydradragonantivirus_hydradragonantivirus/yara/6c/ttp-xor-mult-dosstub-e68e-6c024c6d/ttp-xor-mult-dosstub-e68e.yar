rule TTP_XOR_MULT_DOSStub_e68e {
  strings:
    $key_e68e = { b2 e6 [2] c6 fe [2] 81 fc [2] c6 ed [2] 88 e1 [2] 84 eb [2] 93 e0 [2] 88 ae [2] b5 }

  condition:
    any of them
}