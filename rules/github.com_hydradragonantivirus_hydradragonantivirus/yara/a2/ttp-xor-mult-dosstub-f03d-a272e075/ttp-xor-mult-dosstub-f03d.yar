rule TTP_XOR_MULT_DOSStub_f03d {
  strings:
    $key_f03d = { a4 55 [2] d0 4d [2] 97 4f [2] d0 5e [2] 9e 52 [2] 92 58 [2] 85 53 [2] 9e 1d [2] a3 }

  condition:
    any of them
}