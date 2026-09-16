rule TTP_XOR_MULT_DOSStub_5b2e {
  strings:
    $key_5b2e = { 0f 46 [2] 7b 5e [2] 3c 5c [2] 7b 4d [2] 35 41 [2] 39 4b [2] 2e 40 [2] 35 0e [2] 08 }

  condition:
    any of them
}