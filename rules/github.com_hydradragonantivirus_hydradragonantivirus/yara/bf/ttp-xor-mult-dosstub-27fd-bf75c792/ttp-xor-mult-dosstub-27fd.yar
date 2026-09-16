rule TTP_XOR_MULT_DOSStub_27fd {
  strings:
    $key_27fd = { 73 95 [2] 07 8d [2] 40 8f [2] 07 9e [2] 49 92 [2] 45 98 [2] 52 93 [2] 49 dd [2] 74 }

  condition:
    any of them
}