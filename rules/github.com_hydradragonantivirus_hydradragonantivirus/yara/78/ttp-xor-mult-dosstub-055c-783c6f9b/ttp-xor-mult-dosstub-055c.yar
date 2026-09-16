rule TTP_XOR_MULT_DOSStub_055c {
  strings:
    $key_055c = { 51 34 [2] 25 2c [2] 62 2e [2] 25 3f [2] 6b 33 [2] 67 39 [2] 70 32 [2] 6b 7c [2] 56 }

  condition:
    any of them
}