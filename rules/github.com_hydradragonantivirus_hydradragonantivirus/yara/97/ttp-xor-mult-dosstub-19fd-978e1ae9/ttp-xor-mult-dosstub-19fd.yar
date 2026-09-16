rule TTP_XOR_MULT_DOSStub_19fd {
  strings:
    $key_19fd = { 4d 95 [2] 39 8d [2] 7e 8f [2] 39 9e [2] 77 92 [2] 7b 98 [2] 6c 93 [2] 77 dd [2] 4a }

  condition:
    any of them
}