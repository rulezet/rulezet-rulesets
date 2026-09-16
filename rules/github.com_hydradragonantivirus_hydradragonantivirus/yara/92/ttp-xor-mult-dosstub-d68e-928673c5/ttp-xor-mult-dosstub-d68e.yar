rule TTP_XOR_MULT_DOSStub_d68e {
  strings:
    $key_d68e = { 82 e6 [2] f6 fe [2] b1 fc [2] f6 ed [2] b8 e1 [2] b4 eb [2] a3 e0 [2] b8 ae [2] 85 }

  condition:
    any of them
}