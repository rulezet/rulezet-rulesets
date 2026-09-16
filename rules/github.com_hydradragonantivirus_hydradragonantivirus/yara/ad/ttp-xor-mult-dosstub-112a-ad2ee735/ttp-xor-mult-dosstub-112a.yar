rule TTP_XOR_MULT_DOSStub_112a {
  strings:
    $key_112a = { 45 42 [2] 31 5a [2] 76 58 [2] 31 49 [2] 7f 45 [2] 73 4f [2] 64 44 [2] 7f 0a [2] 42 }

  condition:
    any of them
}