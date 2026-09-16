rule TTP_XOR_MULT_DOSStub_1175 {
  strings:
    $key_1175 = { 45 1d [2] 31 05 [2] 76 07 [2] 31 16 [2] 7f 1a [2] 73 10 [2] 64 1b [2] 7f 55 [2] 42 }

  condition:
    any of them
}