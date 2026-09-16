rule TTP_XOR_MULT_DOSStub_f543 {
  strings:
    $key_f543 = { a1 2b [2] d5 33 [2] 92 31 [2] d5 20 [2] 9b 2c [2] 97 26 [2] 80 2d [2] 9b 63 [2] a6 }

  condition:
    any of them
}