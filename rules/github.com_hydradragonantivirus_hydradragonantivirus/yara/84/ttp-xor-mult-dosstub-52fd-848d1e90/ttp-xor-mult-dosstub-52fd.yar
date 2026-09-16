rule TTP_XOR_MULT_DOSStub_52fd {
  strings:
    $key_52fd = { 06 95 [2] 72 8d [2] 35 8f [2] 72 9e [2] 3c 92 [2] 30 98 [2] 27 93 [2] 3c dd [2] 01 }

  condition:
    any of them
}