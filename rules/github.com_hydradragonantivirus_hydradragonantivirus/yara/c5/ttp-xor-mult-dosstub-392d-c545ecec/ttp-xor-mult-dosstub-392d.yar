rule TTP_XOR_MULT_DOSStub_392d {
  strings:
    $key_392d = { 6d 45 [2] 19 5d [2] 5e 5f [2] 19 4e [2] 57 42 [2] 5b 48 [2] 4c 43 [2] 57 0d [2] 6a }

  condition:
    any of them
}