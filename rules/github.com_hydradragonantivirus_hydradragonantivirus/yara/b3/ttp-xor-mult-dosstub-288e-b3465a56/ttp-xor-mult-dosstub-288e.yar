rule TTP_XOR_MULT_DOSStub_288e {
  strings:
    $key_288e = { 7c e6 [2] 08 fe [2] 4f fc [2] 08 ed [2] 46 e1 [2] 4a eb [2] 5d e0 [2] 46 ae [2] 7b }

  condition:
    any of them
}