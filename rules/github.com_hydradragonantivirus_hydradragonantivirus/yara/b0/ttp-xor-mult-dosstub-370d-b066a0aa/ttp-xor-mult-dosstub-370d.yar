rule TTP_XOR_MULT_DOSStub_370d {
  strings:
    $key_370d = { 63 65 [2] 17 7d [2] 50 7f [2] 17 6e [2] 59 62 [2] 55 68 [2] 42 63 [2] 59 2d [2] 64 }

  condition:
    any of them
}