rule TTP_XOR_MULT_DOSStub_f06a {
  strings:
    $key_f06a = { a4 02 [2] d0 1a [2] 97 18 [2] d0 09 [2] 9e 05 [2] 92 0f [2] 85 04 [2] 9e 4a [2] a3 }

  condition:
    any of them
}