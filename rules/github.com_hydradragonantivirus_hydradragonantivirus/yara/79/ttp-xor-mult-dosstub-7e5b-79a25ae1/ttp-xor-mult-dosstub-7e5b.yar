rule TTP_XOR_MULT_DOSStub_7e5b {
  strings:
    $key_7e5b = { 2a 33 [2] 5e 2b [2] 19 29 [2] 5e 38 [2] 10 34 [2] 1c 3e [2] 0b 35 [2] 10 7b [2] 2d }

  condition:
    any of them
}