rule TTP_XOR_MULT_DOSStub_302e {
  strings:
    $key_302e = { 64 46 [2] 10 5e [2] 57 5c [2] 10 4d [2] 5e 41 [2] 52 4b [2] 45 40 [2] 5e 0e [2] 63 }

  condition:
    any of them
}