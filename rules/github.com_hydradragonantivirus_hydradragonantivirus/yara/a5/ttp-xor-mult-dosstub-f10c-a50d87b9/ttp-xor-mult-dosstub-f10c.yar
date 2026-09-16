rule TTP_XOR_MULT_DOSStub_f10c {
  strings:
    $key_f10c = { a5 64 [2] d1 7c [2] 96 7e [2] d1 6f [2] 9f 63 [2] 93 69 [2] 84 62 [2] 9f 2c [2] a2 }

  condition:
    any of them
}