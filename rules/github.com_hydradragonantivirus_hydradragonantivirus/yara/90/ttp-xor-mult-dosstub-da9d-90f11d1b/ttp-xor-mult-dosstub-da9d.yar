rule TTP_XOR_MULT_DOSStub_da9d {
  strings:
    $key_da9d = { 8e f5 [2] fa ed [2] bd ef [2] fa fe [2] b4 f2 [2] b8 f8 [2] af f3 [2] b4 bd [2] 89 }

  condition:
    any of them
}