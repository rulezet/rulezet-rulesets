rule TTP_XOR_MULT_DOSStub_6f9a {
  strings:
    $key_6f9a = { 3b f2 [2] 4f ea [2] 08 e8 [2] 4f f9 [2] 01 f5 [2] 0d ff [2] 1a f4 [2] 01 ba [2] 3c }

  condition:
    any of them
}