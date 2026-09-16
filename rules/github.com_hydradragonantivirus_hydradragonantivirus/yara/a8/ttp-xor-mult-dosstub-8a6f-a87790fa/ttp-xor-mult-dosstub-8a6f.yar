rule TTP_XOR_MULT_DOSStub_8a6f {
  strings:
    $key_8a6f = { de 07 [2] aa 1f [2] ed 1d [2] aa 0c [2] e4 00 [2] e8 0a [2] ff 01 [2] e4 4f [2] d9 }

  condition:
    any of them
}