rule TTP_XOR_MULT_DOSStub_792c {
  strings:
    $key_792c = { 2d 44 [2] 59 5c [2] 1e 5e [2] 59 4f [2] 17 43 [2] 1b 49 [2] 0c 42 [2] 17 0c [2] 2a }

  condition:
    any of them
}