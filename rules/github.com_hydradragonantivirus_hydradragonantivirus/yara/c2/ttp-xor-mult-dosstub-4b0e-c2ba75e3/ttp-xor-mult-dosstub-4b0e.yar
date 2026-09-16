rule TTP_XOR_MULT_DOSStub_4b0e {
  strings:
    $key_4b0e = { 1f 66 [2] 6b 7e [2] 2c 7c [2] 6b 6d [2] 25 61 [2] 29 6b [2] 3e 60 [2] 25 2e [2] 18 }

  condition:
    any of them
}