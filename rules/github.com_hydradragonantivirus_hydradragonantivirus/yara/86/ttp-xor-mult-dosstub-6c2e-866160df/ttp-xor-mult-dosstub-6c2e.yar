rule TTP_XOR_MULT_DOSStub_6c2e {
  strings:
    $key_6c2e = { 38 46 [2] 4c 5e [2] 0b 5c [2] 4c 4d [2] 02 41 [2] 0e 4b [2] 19 40 [2] 02 0e [2] 3f }

  condition:
    any of them
}