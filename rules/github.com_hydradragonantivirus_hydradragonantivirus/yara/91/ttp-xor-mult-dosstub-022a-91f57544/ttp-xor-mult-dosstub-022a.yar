rule TTP_XOR_MULT_DOSStub_022a {
  strings:
    $key_022a = { 56 42 [2] 22 5a [2] 65 58 [2] 22 49 [2] 6c 45 [2] 60 4f [2] 77 44 [2] 6c 0a [2] 51 }

  condition:
    any of them
}