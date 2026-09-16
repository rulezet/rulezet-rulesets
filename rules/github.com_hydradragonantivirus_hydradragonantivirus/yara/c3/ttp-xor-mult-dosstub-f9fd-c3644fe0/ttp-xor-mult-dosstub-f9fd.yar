rule TTP_XOR_MULT_DOSStub_f9fd {
  strings:
    $key_f9fd = { ad 95 [2] d9 8d [2] 9e 8f [2] d9 9e [2] 97 92 [2] 9b 98 [2] 8c 93 [2] 97 dd [2] aa }

  condition:
    any of them
}