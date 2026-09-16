rule TTP_XOR_MULT_DOSStub_6b9a {
  strings:
    $key_6b9a = { 3f f2 [2] 4b ea [2] 0c e8 [2] 4b f9 [2] 05 f5 [2] 09 ff [2] 1e f4 [2] 05 ba [2] 38 }

  condition:
    any of them
}