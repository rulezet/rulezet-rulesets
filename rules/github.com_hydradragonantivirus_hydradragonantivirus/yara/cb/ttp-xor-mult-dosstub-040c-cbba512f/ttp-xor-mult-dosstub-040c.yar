rule TTP_XOR_MULT_DOSStub_040c {
  strings:
    $key_040c = { 50 64 [2] 24 7c [2] 63 7e [2] 24 6f [2] 6a 63 [2] 66 69 [2] 71 62 [2] 6a 2c [2] 57 }

  condition:
    any of them
}