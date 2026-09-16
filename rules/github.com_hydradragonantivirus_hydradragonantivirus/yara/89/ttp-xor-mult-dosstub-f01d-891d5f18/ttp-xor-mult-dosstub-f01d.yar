rule TTP_XOR_MULT_DOSStub_f01d {
  strings:
    $key_f01d = { a4 75 [2] d0 6d [2] 97 6f [2] d0 7e [2] 9e 72 [2] 92 78 [2] 85 73 [2] 9e 3d [2] a3 }

  condition:
    any of them
}