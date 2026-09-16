rule TTP_XOR_MULT_DOSStub_203d {
  strings:
    $key_203d = { 74 55 [2] 00 4d [2] 47 4f [2] 00 5e [2] 4e 52 [2] 42 58 [2] 55 53 [2] 4e 1d [2] 73 }

  condition:
    any of them
}