rule TTP_XOR_MULT_DOSStub_8aff {
  strings:
    $key_8aff = { de 97 [2] aa 8f [2] ed 8d [2] aa 9c [2] e4 90 [2] e8 9a [2] ff 91 [2] e4 df [2] d9 }

  condition:
    any of them
}