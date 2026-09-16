rule TTP_XOR_MULT_DOSStub_1c3e {
  strings:
    $key_1c3e = { 48 56 [2] 3c 4e [2] 7b 4c [2] 3c 5d [2] 72 51 [2] 7e 5b [2] 69 50 [2] 72 1e [2] 4f }

  condition:
    any of them
}