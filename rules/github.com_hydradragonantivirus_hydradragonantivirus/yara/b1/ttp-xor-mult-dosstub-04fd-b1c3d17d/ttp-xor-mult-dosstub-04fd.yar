rule TTP_XOR_MULT_DOSStub_04fd {
  strings:
    $key_04fd = { 50 95 [2] 24 8d [2] 63 8f [2] 24 9e [2] 6a 92 [2] 66 98 [2] 71 93 [2] 6a dd [2] 57 }

  condition:
    any of them
}