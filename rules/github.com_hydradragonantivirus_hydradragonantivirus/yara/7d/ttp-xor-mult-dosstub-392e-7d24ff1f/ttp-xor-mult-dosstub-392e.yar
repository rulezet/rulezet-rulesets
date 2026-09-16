rule TTP_XOR_MULT_DOSStub_392e {
  strings:
    $key_392e = { 6d 46 [2] 19 5e [2] 5e 5c [2] 19 4d [2] 57 41 [2] 5b 4b [2] 4c 40 [2] 57 0e [2] 6a }

  condition:
    any of them
}