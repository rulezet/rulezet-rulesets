rule TTP_XOR_MULT_DOSStub_66fd {
  strings:
    $key_66fd = { 32 95 [2] 46 8d [2] 01 8f [2] 46 9e [2] 08 92 [2] 04 98 [2] 13 93 [2] 08 dd [2] 35 }

  condition:
    any of them
}