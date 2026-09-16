rule TTP_XOR_MULT_DOSStub_20fd {
  strings:
    $key_20fd = { 74 95 [2] 00 8d [2] 47 8f [2] 00 9e [2] 4e 92 [2] 42 98 [2] 55 93 [2] 4e dd [2] 73 }

  condition:
    any of them
}