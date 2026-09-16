rule TTP_XOR_MULT_DOSStub_429d {
  strings:
    $key_429d = { 16 f5 [2] 62 ed [2] 25 ef [2] 62 fe [2] 2c f2 [2] 20 f8 [2] 37 f3 [2] 2c bd [2] 11 }

  condition:
    any of them
}