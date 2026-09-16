rule TTP_XOR_MULT_DOSStub_f978 {
  strings:
    $key_f978 = { ad 10 [2] d9 08 [2] 9e 0a [2] d9 1b [2] 97 17 [2] 9b 1d [2] 8c 16 [2] 97 58 [2] aa }

  condition:
    any of them
}