rule TTP_XOR_MULT_DOSStub_102a {
  strings:
    $key_102a = { 44 42 [2] 30 5a [2] 77 58 [2] 30 49 [2] 7e 45 [2] 72 4f [2] 65 44 [2] 7e 0a [2] 43 }

  condition:
    any of them
}