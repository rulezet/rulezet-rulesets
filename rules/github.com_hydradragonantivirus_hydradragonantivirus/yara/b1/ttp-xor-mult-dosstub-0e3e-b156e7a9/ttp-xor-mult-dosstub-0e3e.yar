rule TTP_XOR_MULT_DOSStub_0e3e {
  strings:
    $key_0e3e = { 5a 56 [2] 2e 4e [2] 69 4c [2] 2e 5d [2] 60 51 [2] 6c 5b [2] 7b 50 [2] 60 1e [2] 5d }

  condition:
    any of them
}