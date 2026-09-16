rule TTP_XOR_MULT_DOSStub_8a78 {
  strings:
    $key_8a78 = { de 10 [2] aa 08 [2] ed 0a [2] aa 1b [2] e4 17 [2] e8 1d [2] ff 16 [2] e4 58 [2] d9 }

  condition:
    any of them
}