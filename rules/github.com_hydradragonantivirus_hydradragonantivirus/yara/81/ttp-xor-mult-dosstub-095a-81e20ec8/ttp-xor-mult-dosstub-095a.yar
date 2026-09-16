rule TTP_XOR_MULT_DOSStub_095a {
  strings:
    $key_095a = { 5d 32 [2] 29 2a [2] 6e 28 [2] 29 39 [2] 67 35 [2] 6b 3f [2] 7c 34 [2] 67 7a [2] 5a }

  condition:
    any of them
}