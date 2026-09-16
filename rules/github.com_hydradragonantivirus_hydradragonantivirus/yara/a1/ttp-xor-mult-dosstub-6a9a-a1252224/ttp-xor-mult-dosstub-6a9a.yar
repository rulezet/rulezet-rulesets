rule TTP_XOR_MULT_DOSStub_6a9a {
  strings:
    $key_6a9a = { 3e f2 [2] 4a ea [2] 0d e8 [2] 4a f9 [2] 04 f5 [2] 08 ff [2] 1f f4 [2] 04 ba [2] 39 }

  condition:
    any of them
}