rule TTP_XOR_MULT_DOSStub_c68e {
  strings:
    $key_c68e = { 92 e6 [2] e6 fe [2] a1 fc [2] e6 ed [2] a8 e1 [2] a4 eb [2] b3 e0 [2] a8 ae [2] 95 }

  condition:
    any of them
}