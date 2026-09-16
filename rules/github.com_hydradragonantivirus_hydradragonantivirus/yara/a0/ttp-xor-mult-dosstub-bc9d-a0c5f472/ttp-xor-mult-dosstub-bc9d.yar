rule TTP_XOR_MULT_DOSStub_bc9d {
  strings:
    $key_bc9d = { e8 f5 [2] 9c ed [2] db ef [2] 9c fe [2] d2 f2 [2] de f8 [2] c9 f3 [2] d2 bd [2] ef }

  condition:
    any of them
}