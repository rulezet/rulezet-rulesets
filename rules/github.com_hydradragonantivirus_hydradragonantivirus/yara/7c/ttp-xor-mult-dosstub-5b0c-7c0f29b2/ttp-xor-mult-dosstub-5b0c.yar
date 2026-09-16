rule TTP_XOR_MULT_DOSStub_5b0c {
  strings:
    $key_5b0c = { 0f 64 [2] 7b 7c [2] 3c 7e [2] 7b 6f [2] 35 63 [2] 39 69 [2] 2e 62 [2] 35 2c [2] 08 }

  condition:
    any of them
}