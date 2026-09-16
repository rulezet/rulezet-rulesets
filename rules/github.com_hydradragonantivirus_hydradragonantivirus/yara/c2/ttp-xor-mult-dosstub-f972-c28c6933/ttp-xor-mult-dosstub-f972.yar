rule TTP_XOR_MULT_DOSStub_f972 {
  strings:
    $key_f972 = { ad 1a [2] d9 02 [2] 9e 00 [2] d9 11 [2] 97 1d [2] 9b 17 [2] 8c 1c [2] 97 52 [2] aa }

  condition:
    any of them
}