rule TTP_XOR_MULT_DOSStub_e10c {
  strings:
    $key_e10c = { b5 64 [2] c1 7c [2] 86 7e [2] c1 6f [2] 8f 63 [2] 83 69 [2] 94 62 [2] 8f 2c [2] b2 }

  condition:
    any of them
}