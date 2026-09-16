rule TTP_XOR_MULT_DOSStub_ef8e {
  strings:
    $key_ef8e = { bb e6 [2] cf fe [2] 88 fc [2] cf ed [2] 81 e1 [2] 8d eb [2] 9a e0 [2] 81 ae [2] bc }

  condition:
    any of them
}