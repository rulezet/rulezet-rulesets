rule TTP_XOR_MULT_DOSStub_4f3e {
  strings:
    $key_4f3e = { 1b 56 [2] 6f 4e [2] 28 4c [2] 6f 5d [2] 21 51 [2] 2d 5b [2] 3a 50 [2] 21 1e [2] 1c }

  condition:
    any of them
}