rule TTP_XOR_MULT_DOSStub_8a64 {
  strings:
    $key_8a64 = { de 0c [2] aa 14 [2] ed 16 [2] aa 07 [2] e4 0b [2] e8 01 [2] ff 0a [2] e4 44 [2] d9 }

  condition:
    any of them
}