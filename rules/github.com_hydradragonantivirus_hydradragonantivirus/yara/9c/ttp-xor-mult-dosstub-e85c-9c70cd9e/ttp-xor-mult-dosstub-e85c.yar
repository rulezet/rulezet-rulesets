rule TTP_XOR_MULT_DOSStub_e85c {
  strings:
    $key_e85c = { bc 34 [2] c8 2c [2] 8f 2e [2] c8 3f [2] 86 33 [2] 8a 39 [2] 9d 32 [2] 86 7c [2] bb }

  condition:
    any of them
}