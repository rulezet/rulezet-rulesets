rule TTP_XOR_MULT_DOSStub_8a24 {
  strings:
    $key_8a24 = { de 4c [2] aa 54 [2] ed 56 [2] aa 47 [2] e4 4b [2] e8 41 [2] ff 4a [2] e4 04 [2] d9 }

  condition:
    any of them
}