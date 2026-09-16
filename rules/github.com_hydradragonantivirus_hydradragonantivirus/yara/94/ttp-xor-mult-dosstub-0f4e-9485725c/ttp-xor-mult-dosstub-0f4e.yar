rule TTP_XOR_MULT_DOSStub_0f4e {
  strings:
    $key_0f4e = { 5b 26 [2] 2f 3e [2] 68 3c [2] 2f 2d [2] 61 21 [2] 6d 2b [2] 7a 20 [2] 61 6e [2] 5c }

  condition:
    any of them
}