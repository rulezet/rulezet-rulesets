rule TTP_XOR_MULT_DOSStub_396e {
  strings:
    $key_396e = { 6d 06 [2] 19 1e [2] 5e 1c [2] 19 0d [2] 57 01 [2] 5b 0b [2] 4c 00 [2] 57 4e [2] 6a }

  condition:
    any of them
}