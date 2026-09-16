rule TTP_XOR_MULT_DOSStub_43fd {
  strings:
    $key_43fd = { 17 95 [2] 63 8d [2] 24 8f [2] 63 9e [2] 2d 92 [2] 21 98 [2] 36 93 [2] 2d dd [2] 10 }

  condition:
    any of them
}