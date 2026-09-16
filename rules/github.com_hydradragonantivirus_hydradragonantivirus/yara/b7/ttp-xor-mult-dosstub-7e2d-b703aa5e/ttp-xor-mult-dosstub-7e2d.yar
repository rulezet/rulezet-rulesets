rule TTP_XOR_MULT_DOSStub_7e2d {
  strings:
    $key_7e2d = { 2a 45 [2] 5e 5d [2] 19 5f [2] 5e 4e [2] 10 42 [2] 1c 48 [2] 0b 43 [2] 10 0d [2] 2d }

  condition:
    any of them
}