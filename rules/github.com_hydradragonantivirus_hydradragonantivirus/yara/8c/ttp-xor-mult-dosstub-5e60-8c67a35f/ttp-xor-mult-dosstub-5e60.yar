rule TTP_XOR_MULT_DOSStub_5e60 {
  strings:
    $key_5e60 = { 0a 08 [2] 7e 10 [2] 39 12 [2] 7e 03 [2] 30 0f [2] 3c 05 [2] 2b 0e [2] 30 40 [2] 0d }

  condition:
    any of them
}