rule TTP_XOR_MULT_DOSStub_36fd {
  strings:
    $key_36fd = { 62 95 [2] 16 8d [2] 51 8f [2] 16 9e [2] 58 92 [2] 54 98 [2] 43 93 [2] 58 dd [2] 65 }

  condition:
    any of them
}