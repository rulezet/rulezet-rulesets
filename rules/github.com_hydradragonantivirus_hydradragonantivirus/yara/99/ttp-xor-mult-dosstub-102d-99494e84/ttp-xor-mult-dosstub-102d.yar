rule TTP_XOR_MULT_DOSStub_102d {
  strings:
    $key_102d = { 44 45 [2] 30 5d [2] 77 5f [2] 30 4e [2] 7e 42 [2] 72 48 [2] 65 43 [2] 7e 0d [2] 43 }

  condition:
    any of them
}