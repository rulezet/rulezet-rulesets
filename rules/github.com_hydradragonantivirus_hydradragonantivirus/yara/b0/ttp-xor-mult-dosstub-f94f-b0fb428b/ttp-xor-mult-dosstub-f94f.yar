rule TTP_XOR_MULT_DOSStub_f94f {
  strings:
    $key_f94f = { ad 27 [2] d9 3f [2] 9e 3d [2] d9 2c [2] 97 20 [2] 9b 2a [2] 8c 21 [2] 97 6f [2] aa }

  condition:
    any of them
}