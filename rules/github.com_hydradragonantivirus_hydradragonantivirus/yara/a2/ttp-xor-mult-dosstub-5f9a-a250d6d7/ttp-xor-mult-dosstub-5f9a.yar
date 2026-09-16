rule TTP_XOR_MULT_DOSStub_5f9a {
  strings:
    $key_5f9a = { 0b f2 [2] 7f ea [2] 38 e8 [2] 7f f9 [2] 31 f5 [2] 3d ff [2] 2a f4 [2] 31 ba [2] 0c }

  condition:
    any of them
}