rule TTP_XOR_MULT_DOSStub_8a71 {
  strings:
    $key_8a71 = { de 19 [2] aa 01 [2] ed 03 [2] aa 12 [2] e4 1e [2] e8 14 [2] ff 1f [2] e4 51 [2] d9 }

  condition:
    any of them
}