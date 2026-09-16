rule TTP_XOR_MULT_DOSStub_08fd {
  strings:
    $key_08fd = { 5c 95 [2] 28 8d [2] 6f 8f [2] 28 9e [2] 66 92 [2] 6a 98 [2] 7d 93 [2] 66 dd [2] 5b }

  condition:
    any of them
}