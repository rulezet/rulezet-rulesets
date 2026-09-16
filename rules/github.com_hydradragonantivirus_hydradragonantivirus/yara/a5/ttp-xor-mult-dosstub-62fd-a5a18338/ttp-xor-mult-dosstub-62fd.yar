rule TTP_XOR_MULT_DOSStub_62fd {
  strings:
    $key_62fd = { 36 95 [2] 42 8d [2] 05 8f [2] 42 9e [2] 0c 92 [2] 00 98 [2] 17 93 [2] 0c dd [2] 31 }

  condition:
    any of them
}