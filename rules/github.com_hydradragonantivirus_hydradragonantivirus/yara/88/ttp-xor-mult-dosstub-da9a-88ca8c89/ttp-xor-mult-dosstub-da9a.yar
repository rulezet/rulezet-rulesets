rule TTP_XOR_MULT_DOSStub_da9a {
  strings:
    $key_da9a = { 8e f2 [2] fa ea [2] bd e8 [2] fa f9 [2] b4 f5 [2] b8 ff [2] af f4 [2] b4 ba [2] 89 }

  condition:
    any of them
}