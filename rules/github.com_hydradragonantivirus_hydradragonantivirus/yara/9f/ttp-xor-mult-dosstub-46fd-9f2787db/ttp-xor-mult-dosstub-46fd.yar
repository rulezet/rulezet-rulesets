rule TTP_XOR_MULT_DOSStub_46fd {
  strings:
    $key_46fd = { 12 95 [2] 66 8d [2] 21 8f [2] 66 9e [2] 28 92 [2] 24 98 [2] 33 93 [2] 28 dd [2] 15 }

  condition:
    any of them
}