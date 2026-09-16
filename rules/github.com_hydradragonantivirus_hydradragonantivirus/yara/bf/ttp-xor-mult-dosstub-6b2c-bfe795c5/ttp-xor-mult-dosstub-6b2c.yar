rule TTP_XOR_MULT_DOSStub_6b2c {
  strings:
    $key_6b2c = { 3f 44 [2] 4b 5c [2] 0c 5e [2] 4b 4f [2] 05 43 [2] 09 49 [2] 1e 42 [2] 05 0c [2] 38 }

  condition:
    any of them
}