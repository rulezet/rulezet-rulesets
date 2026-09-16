rule TTP_XOR_MULT_DOSStub_07fd {
  strings:
    $key_07fd = { 53 95 [2] 27 8d [2] 60 8f [2] 27 9e [2] 69 92 [2] 65 98 [2] 72 93 [2] 69 dd [2] 54 }

  condition:
    any of them
}