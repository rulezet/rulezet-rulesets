rule TTP_XOR_MULT_DOSStub_015c {
  strings:
    $key_015c = { 55 34 [2] 21 2c [2] 66 2e [2] 21 3f [2] 6f 33 [2] 63 39 [2] 74 32 [2] 6f 7c [2] 52 }

  condition:
    any of them
}