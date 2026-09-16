rule TTP_XOR_MULT_DOSStub_39fd {
  strings:
    $key_39fd = { 6d 95 [2] 19 8d [2] 5e 8f [2] 19 9e [2] 57 92 [2] 5b 98 [2] 4c 93 [2] 57 dd [2] 6a }

  condition:
    any of them
}