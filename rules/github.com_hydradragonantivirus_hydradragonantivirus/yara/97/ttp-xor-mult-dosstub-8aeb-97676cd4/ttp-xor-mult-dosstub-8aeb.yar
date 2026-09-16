rule TTP_XOR_MULT_DOSStub_8aeb {
  strings:
    $key_8aeb = { de 83 [2] aa 9b [2] ed 99 [2] aa 88 [2] e4 84 [2] e8 8e [2] ff 85 [2] e4 cb [2] d9 }

  condition:
    any of them
}