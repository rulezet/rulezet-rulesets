rule TTP_XOR_MULT_DOSStub_f90c {
  strings:
    $key_f90c = { ad 64 [2] d9 7c [2] 9e 7e [2] d9 6f [2] 97 63 [2] 9b 69 [2] 8c 62 [2] 97 2c [2] aa }

  condition:
    any of them
}