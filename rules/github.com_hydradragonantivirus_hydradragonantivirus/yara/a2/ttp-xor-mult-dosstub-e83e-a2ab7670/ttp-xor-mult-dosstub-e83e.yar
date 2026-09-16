rule TTP_XOR_MULT_DOSStub_e83e {
  strings:
    $key_e83e = { bc 56 [2] c8 4e [2] 8f 4c [2] c8 5d [2] 86 51 [2] 8a 5b [2] 9d 50 [2] 86 1e [2] bb }

  condition:
    any of them
}