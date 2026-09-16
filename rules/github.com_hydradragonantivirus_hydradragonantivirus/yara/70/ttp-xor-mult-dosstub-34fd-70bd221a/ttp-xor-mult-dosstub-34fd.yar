rule TTP_XOR_MULT_DOSStub_34fd {
  strings:
    $key_34fd = { 60 95 [2] 14 8d [2] 53 8f [2] 14 9e [2] 5a 92 [2] 56 98 [2] 41 93 [2] 5a dd [2] 67 }

  condition:
    any of them
}