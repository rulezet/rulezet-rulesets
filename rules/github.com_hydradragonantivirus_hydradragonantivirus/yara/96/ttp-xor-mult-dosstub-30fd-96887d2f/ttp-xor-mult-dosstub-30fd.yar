rule TTP_XOR_MULT_DOSStub_30fd {
  strings:
    $key_30fd = { 64 95 [2] 10 8d [2] 57 8f [2] 10 9e [2] 5e 92 [2] 52 98 [2] 45 93 [2] 5e dd [2] 63 }

  condition:
    any of them
}