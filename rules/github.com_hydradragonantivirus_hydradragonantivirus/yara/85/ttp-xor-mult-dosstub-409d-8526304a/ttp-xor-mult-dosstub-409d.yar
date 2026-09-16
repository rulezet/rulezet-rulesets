rule TTP_XOR_MULT_DOSStub_409d {
  strings:
    $key_409d = { 14 f5 [2] 60 ed [2] 27 ef [2] 60 fe [2] 2e f2 [2] 22 f8 [2] 35 f3 [2] 2e bd [2] 13 }

  condition:
    any of them
}