rule TTP_XOR_MULT_DOSStub_192d {
  strings:
    $key_192d = { 4d 45 [2] 39 5d [2] 7e 5f [2] 39 4e [2] 77 42 [2] 7b 48 [2] 6c 43 [2] 77 0d [2] 4a }

  condition:
    any of them
}