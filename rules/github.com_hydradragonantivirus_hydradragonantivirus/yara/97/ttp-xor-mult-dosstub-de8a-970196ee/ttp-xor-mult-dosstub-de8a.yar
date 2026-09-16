rule TTP_XOR_MULT_DOSStub_de8a {
  strings:
    $key_de8a = { 8a e2 [2] fe fa [2] b9 f8 [2] fe e9 [2] b0 e5 [2] bc ef [2] ab e4 [2] b0 aa [2] 8d }

  condition:
    any of them
}