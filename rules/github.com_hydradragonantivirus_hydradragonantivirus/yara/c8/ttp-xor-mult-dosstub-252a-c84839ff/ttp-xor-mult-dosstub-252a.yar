rule TTP_XOR_MULT_DOSStub_252a {
  strings:
    $key_252a = { 71 42 [2] 05 5a [2] 42 58 [2] 05 49 [2] 4b 45 [2] 47 4f [2] 50 44 [2] 4b 0a [2] 76 }

  condition:
    any of them
}