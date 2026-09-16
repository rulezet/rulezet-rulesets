rule TTP_XOR_MULT_DOSStub_0d4e {
  strings:
    $key_0d4e = { 59 26 [2] 2d 3e [2] 6a 3c [2] 2d 2d [2] 63 21 [2] 6f 2b [2] 78 20 [2] 63 6e [2] 5e }

  condition:
    any of them
}