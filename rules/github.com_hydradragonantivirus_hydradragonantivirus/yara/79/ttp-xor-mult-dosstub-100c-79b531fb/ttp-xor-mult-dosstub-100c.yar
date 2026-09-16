rule TTP_XOR_MULT_DOSStub_100c {
  strings:
    $key_100c = { 44 64 [2] 30 7c [2] 77 7e [2] 30 6f [2] 7e 63 [2] 72 69 [2] 65 62 [2] 7e 2c [2] 43 }

  condition:
    any of them
}