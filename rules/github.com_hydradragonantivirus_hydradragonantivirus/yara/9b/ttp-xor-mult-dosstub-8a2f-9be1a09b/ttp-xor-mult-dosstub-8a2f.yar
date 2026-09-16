rule TTP_XOR_MULT_DOSStub_8a2f {
  strings:
    $key_8a2f = { de 47 [2] aa 5f [2] ed 5d [2] aa 4c [2] e4 40 [2] e8 4a [2] ff 41 [2] e4 0f [2] d9 }

  condition:
    any of them
}