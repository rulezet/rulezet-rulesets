rule TTP_XOR_MULT_DOSStub_7b3e {
  strings:
    $key_7b3e = { 2f 56 [2] 5b 4e [2] 1c 4c [2] 5b 5d [2] 15 51 [2] 19 5b [2] 0e 50 [2] 15 1e [2] 28 }

  condition:
    any of them
}