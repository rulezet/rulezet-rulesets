rule TTP_XOR_MULT_DOSStub_207a {
  strings:
    $key_207a = { 74 12 [2] 00 0a [2] 47 08 [2] 00 19 [2] 4e 15 [2] 42 1f [2] 55 14 [2] 4e 5a [2] 73 }

  condition:
    any of them
}