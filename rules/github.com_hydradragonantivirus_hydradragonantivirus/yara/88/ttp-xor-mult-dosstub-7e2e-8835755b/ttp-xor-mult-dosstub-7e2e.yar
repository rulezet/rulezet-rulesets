rule TTP_XOR_MULT_DOSStub_7e2e {
  strings:
    $key_7e2e = { 2a 46 [2] 5e 5e [2] 19 5c [2] 5e 4d [2] 10 41 [2] 1c 4b [2] 0b 40 [2] 10 0e [2] 2d }

  condition:
    any of them
}