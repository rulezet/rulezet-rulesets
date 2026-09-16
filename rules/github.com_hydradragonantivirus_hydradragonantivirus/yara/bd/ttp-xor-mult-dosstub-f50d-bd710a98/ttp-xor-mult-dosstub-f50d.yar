rule TTP_XOR_MULT_DOSStub_f50d {
  strings:
    $key_f50d = { a1 65 [2] d5 7d [2] 92 7f [2] d5 6e [2] 9b 62 [2] 97 68 [2] 80 63 [2] 9b 2d [2] a6 }

  condition:
    any of them
}