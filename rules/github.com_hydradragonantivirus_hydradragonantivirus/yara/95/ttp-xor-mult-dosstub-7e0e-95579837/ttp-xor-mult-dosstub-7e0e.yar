rule TTP_XOR_MULT_DOSStub_7e0e {
  strings:
    $key_7e0e = { 2a 66 [2] 5e 7e [2] 19 7c [2] 5e 6d [2] 10 61 [2] 1c 6b [2] 0b 60 [2] 10 2e [2] 2d }

  condition:
    any of them
}