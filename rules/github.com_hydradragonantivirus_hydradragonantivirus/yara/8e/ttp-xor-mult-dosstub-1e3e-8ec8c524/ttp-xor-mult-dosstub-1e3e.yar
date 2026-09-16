rule TTP_XOR_MULT_DOSStub_1e3e {
  strings:
    $key_1e3e = { 4a 56 [2] 3e 4e [2] 79 4c [2] 3e 5d [2] 70 51 [2] 7c 5b [2] 6b 50 [2] 70 1e [2] 4d }

  condition:
    any of them
}