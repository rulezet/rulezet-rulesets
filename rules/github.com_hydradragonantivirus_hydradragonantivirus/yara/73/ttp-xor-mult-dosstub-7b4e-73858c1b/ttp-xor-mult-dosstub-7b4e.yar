rule TTP_XOR_MULT_DOSStub_7b4e {
  strings:
    $key_7b4e = { 2f 26 [2] 5b 3e [2] 1c 3c [2] 5b 2d [2] 15 21 [2] 19 2b [2] 0e 20 [2] 15 6e [2] 28 }

  condition:
    any of them
}