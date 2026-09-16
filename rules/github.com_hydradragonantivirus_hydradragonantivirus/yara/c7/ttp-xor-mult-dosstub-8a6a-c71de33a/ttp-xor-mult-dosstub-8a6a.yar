rule TTP_XOR_MULT_DOSStub_8a6a {
  strings:
    $key_8a6a = { de 02 [2] aa 1a [2] ed 18 [2] aa 09 [2] e4 05 [2] e8 0f [2] ff 04 [2] e4 4a [2] d9 }

  condition:
    any of them
}