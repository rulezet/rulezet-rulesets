rule TTP_XOR_MULT_DOSStub_06fd {
  strings:
    $key_06fd = { 52 95 [2] 26 8d [2] 61 8f [2] 26 9e [2] 68 92 [2] 64 98 [2] 73 93 [2] 68 dd [2] 55 }

  condition:
    any of them
}