rule TTP_XOR_MULT_DOSStub_4b3e {
  strings:
    $key_4b3e = { 1f 56 [2] 6b 4e [2] 2c 4c [2] 6b 5d [2] 25 51 [2] 29 5b [2] 3e 50 [2] 25 1e [2] 18 }

  condition:
    any of them
}