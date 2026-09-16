rule TTP_XOR_MULT_DOSStub_5b3e {
  strings:
    $key_5b3e = { 0f 56 [2] 7b 4e [2] 3c 4c [2] 7b 5d [2] 35 51 [2] 39 5b [2] 2e 50 [2] 35 1e [2] 08 }

  condition:
    any of them
}