rule TTP_XOR_MULT_DOSStub_392a {
  strings:
    $key_392a = { 6d 42 [2] 19 5a [2] 5e 58 [2] 19 49 [2] 57 45 [2] 5b 4f [2] 4c 44 [2] 57 0a [2] 6a }

  condition:
    any of them
}