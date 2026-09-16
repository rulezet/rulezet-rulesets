rule TTP_XOR_MULT_DOSStub_5e2d {
  strings:
    $key_5e2d = { 0a 45 [2] 7e 5d [2] 39 5f [2] 7e 4e [2] 30 42 [2] 3c 48 [2] 2b 43 [2] 30 0d [2] 0d }

  condition:
    any of them
}