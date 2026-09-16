rule TTP_XOR_MULT_DOSStub_e78e {
  strings:
    $key_e78e = { b3 e6 [2] c7 fe [2] 80 fc [2] c7 ed [2] 89 e1 [2] 85 eb [2] 92 e0 [2] 89 ae [2] b4 }

  condition:
    any of them
}