rule TTP_XOR_MULT_DOSStub_f55e {
  strings:
    $key_f55e = { a1 36 [2] d5 2e [2] 92 2c [2] d5 3d [2] 9b 31 [2] 97 3b [2] 80 30 [2] 9b 7e [2] a6 }

  condition:
    any of them
}