rule TTP_XOR_MULT_DOSStub_7e1e {
  strings:
    $key_7e1e = { 2a 76 [2] 5e 6e [2] 19 6c [2] 5e 7d [2] 10 71 [2] 1c 7b [2] 0b 70 [2] 10 3e [2] 2d }

  condition:
    any of them
}