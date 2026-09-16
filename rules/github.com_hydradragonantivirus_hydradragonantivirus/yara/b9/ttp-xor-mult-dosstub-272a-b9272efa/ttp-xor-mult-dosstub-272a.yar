rule TTP_XOR_MULT_DOSStub_272a {
  strings:
    $key_272a = { 73 42 [2] 07 5a [2] 40 58 [2] 07 49 [2] 49 45 [2] 45 4f [2] 52 44 [2] 49 0a [2] 74 }

  condition:
    any of them
}