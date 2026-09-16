rule TTP_XOR_MULT_DOSStub_770c {
  strings:
    $key_770c = { 23 64 [2] 57 7c [2] 10 7e [2] 57 6f [2] 19 63 [2] 15 69 [2] 02 62 [2] 19 2c [2] 24 }

  condition:
    any of them
}