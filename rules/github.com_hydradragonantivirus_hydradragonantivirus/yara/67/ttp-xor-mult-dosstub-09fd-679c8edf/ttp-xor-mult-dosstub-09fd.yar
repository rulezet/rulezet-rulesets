rule TTP_XOR_MULT_DOSStub_09fd {
  strings:
    $key_09fd = { 5d 95 [2] 29 8d [2] 6e 8f [2] 29 9e [2] 67 92 [2] 6b 98 [2] 7c 93 [2] 67 dd [2] 5a }

  condition:
    any of them
}