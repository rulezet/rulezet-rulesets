rule TTP_XOR_MULT_DOSStub_f56a {
  strings:
    $key_f56a = { a1 02 [2] d5 1a [2] 92 18 [2] d5 09 [2] 9b 05 [2] 97 0f [2] 80 04 [2] 9b 4a [2] a6 }

  condition:
    any of them
}