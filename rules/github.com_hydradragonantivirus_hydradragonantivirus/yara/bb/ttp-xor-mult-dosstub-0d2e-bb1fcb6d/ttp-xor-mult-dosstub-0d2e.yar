rule TTP_XOR_MULT_DOSStub_0d2e {
  strings:
    $key_0d2e = { 59 46 [2] 2d 5e [2] 6a 5c [2] 2d 4d [2] 63 41 [2] 6f 4b [2] 78 40 [2] 63 0e [2] 5e }

  condition:
    any of them
}