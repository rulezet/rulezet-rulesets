rule TTP_XOR_MULT_DOSStub_192a {
  strings:
    $key_192a = { 4d 42 [2] 39 5a [2] 7e 58 [2] 39 49 [2] 77 45 [2] 7b 4f [2] 6c 44 [2] 77 0a [2] 4a }

  condition:
    any of them
}