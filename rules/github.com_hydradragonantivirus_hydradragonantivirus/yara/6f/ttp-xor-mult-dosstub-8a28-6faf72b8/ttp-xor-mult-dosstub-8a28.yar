rule TTP_XOR_MULT_DOSStub_8a28 {
  strings:
    $key_8a28 = { de 40 [2] aa 58 [2] ed 5a [2] aa 4b [2] e4 47 [2] e8 4d [2] ff 46 [2] e4 08 [2] d9 }

  condition:
    any of them
}