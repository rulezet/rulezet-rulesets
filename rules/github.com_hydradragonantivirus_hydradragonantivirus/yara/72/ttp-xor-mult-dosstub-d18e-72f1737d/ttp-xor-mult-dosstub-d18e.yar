rule TTP_XOR_MULT_DOSStub_d18e {
  strings:
    $key_d18e = { 85 e6 [2] f1 fe [2] b6 fc [2] f1 ed [2] bf e1 [2] b3 eb [2] a4 e0 [2] bf ae [2] 82 }

  condition:
    any of them
}