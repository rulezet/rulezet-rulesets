rule TTP_XOR_MULT_DOSStub_b98a {
  strings:
    $key_b98a = { ed e2 [2] 99 fa [2] de f8 [2] 99 e9 [2] d7 e5 [2] db ef [2] cc e4 [2] d7 aa [2] ea }

  condition:
    any of them
}