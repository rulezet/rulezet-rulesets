rule TTP_XOR_MULT_DOSStub_8afd {
  strings:
    $key_8afd = { de 95 [2] aa 8d [2] ed 8f [2] aa 9e [2] e4 92 [2] e8 98 [2] ff 93 [2] e4 dd [2] d9 }

  condition:
    any of them
}