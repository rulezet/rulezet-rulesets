rule TTP_XOR_MULT_DOSStub_f945 {
  strings:
    $key_f945 = { ad 2d [2] d9 35 [2] 9e 37 [2] d9 26 [2] 97 2a [2] 9b 20 [2] 8c 2b [2] 97 65 [2] aa }

  condition:
    any of them
}