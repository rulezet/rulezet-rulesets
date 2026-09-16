rule TTP_XOR_MULT_DOSStub_7e7d {
  strings:
    $key_7e7d = { 2a 15 [2] 5e 0d [2] 19 0f [2] 5e 1e [2] 10 12 [2] 1c 18 [2] 0b 13 [2] 10 5d [2] 2d }

  condition:
    any of them
}