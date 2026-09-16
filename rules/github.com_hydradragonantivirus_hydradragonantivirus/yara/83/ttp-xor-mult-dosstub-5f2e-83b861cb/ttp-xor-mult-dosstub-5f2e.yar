rule TTP_XOR_MULT_DOSStub_5f2e {
  strings:
    $key_5f2e = { 0b 46 [2] 7f 5e [2] 38 5c [2] 7f 4d [2] 31 41 [2] 3d 4b [2] 2a 40 [2] 31 0e [2] 0c }

  condition:
    any of them
}