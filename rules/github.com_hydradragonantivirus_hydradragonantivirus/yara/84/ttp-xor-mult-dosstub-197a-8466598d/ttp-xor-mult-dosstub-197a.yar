rule TTP_XOR_MULT_DOSStub_197a {
  strings:
    $key_197a = { 4d 12 [2] 39 0a [2] 7e 08 [2] 39 19 [2] 77 15 [2] 7b 1f [2] 6c 14 [2] 77 5a [2] 4a }

  condition:
    any of them
}