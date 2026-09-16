rule TTP_XOR_MULT_DOSStub_0e2e {
  strings:
    $key_0e2e = { 5a 46 [2] 2e 5e [2] 69 5c [2] 2e 4d [2] 60 41 [2] 6c 4b [2] 7b 40 [2] 60 0e [2] 5d }

  condition:
    any of them
}