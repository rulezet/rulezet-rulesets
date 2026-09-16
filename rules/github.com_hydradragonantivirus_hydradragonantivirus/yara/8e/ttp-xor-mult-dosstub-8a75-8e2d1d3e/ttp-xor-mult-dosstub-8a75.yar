rule TTP_XOR_MULT_DOSStub_8a75 {
  strings:
    $key_8a75 = { de 1d [2] aa 05 [2] ed 07 [2] aa 16 [2] e4 1a [2] e8 10 [2] ff 1b [2] e4 55 [2] d9 }

  condition:
    any of them
}