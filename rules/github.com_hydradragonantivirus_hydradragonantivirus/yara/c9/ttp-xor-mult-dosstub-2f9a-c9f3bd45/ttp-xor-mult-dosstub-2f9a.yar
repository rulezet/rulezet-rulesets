rule TTP_XOR_MULT_DOSStub_2f9a {
  strings:
    $key_2f9a = { 7b f2 [2] 0f ea [2] 48 e8 [2] 0f f9 [2] 41 f5 [2] 4d ff [2] 5a f4 [2] 41 ba [2] 7c }

  condition:
    any of them
}