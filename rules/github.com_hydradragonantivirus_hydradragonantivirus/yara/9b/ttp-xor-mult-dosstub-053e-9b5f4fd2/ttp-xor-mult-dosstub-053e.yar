rule TTP_XOR_MULT_DOSStub_053e {
  strings:
    $key_053e = { 51 56 [2] 25 4e [2] 62 4c [2] 25 5d [2] 6b 51 [2] 67 5b [2] 70 50 [2] 6b 1e [2] 56 }

  condition:
    any of them
}