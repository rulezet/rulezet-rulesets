rule TTP_XOR_MULT_DOSStub_8ae1 {
  strings:
    $key_8ae1 = { de 89 [2] aa 91 [2] ed 93 [2] aa 82 [2] e4 8e [2] e8 84 [2] ff 8f [2] e4 c1 [2] d9 }

  condition:
    any of them
}