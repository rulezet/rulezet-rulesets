rule TTP_XOR_MULT_DOSStub_f0fd {
  strings:
    $key_f0fd = { a4 95 [2] d0 8d [2] 97 8f [2] d0 9e [2] 9e 92 [2] 92 98 [2] 85 93 [2] 9e dd [2] a3 }

  condition:
    any of them
}