rule TTP_XOR_MULT_DOSStub_606a {
  strings:
    $key_606a = { 34 02 [2] 40 1a [2] 07 18 [2] 40 09 [2] 0e 05 [2] 02 0f [2] 15 04 [2] 0e 4a [2] 33 }

  condition:
    any of them
}