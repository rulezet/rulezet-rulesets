rule TTP_XOR_MULT_DOSStub_37fd {
  strings:
    $key_37fd = { 63 95 [2] 17 8d [2] 50 8f [2] 17 9e [2] 59 92 [2] 55 98 [2] 42 93 [2] 59 dd [2] 64 }

  condition:
    any of them
}