rule TTP_XOR_MULT_DOSStub_f96a {
  strings:
    $key_f96a = { ad 02 [2] d9 1a [2] 9e 18 [2] d9 09 [2] 97 05 [2] 9b 0f [2] 8c 04 [2] 97 4a [2] aa }

  condition:
    any of them
}