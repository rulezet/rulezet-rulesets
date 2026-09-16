rule TTP_XOR_MULT_DOSStub_e88e {
  strings:
    $key_e88e = { bc e6 [2] c8 fe [2] 8f fc [2] c8 ed [2] 86 e1 [2] 8a eb [2] 9d e0 [2] 86 ae [2] bb }

  condition:
    any of them
}