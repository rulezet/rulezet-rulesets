rule TTP_XOR_MULT_DOSStub_ec10 {
  strings:
    $key_ec10 = { b8 78 [2] cc 60 [2] 8b 62 [2] cc 73 [2] 82 7f [2] 8e 75 [2] 99 7e [2] 82 30 [2] bf }

  condition:
    any of them
}