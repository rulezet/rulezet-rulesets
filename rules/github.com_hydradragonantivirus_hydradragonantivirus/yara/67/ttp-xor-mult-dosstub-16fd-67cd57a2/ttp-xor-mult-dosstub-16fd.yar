rule TTP_XOR_MULT_DOSStub_16fd {
  strings:
    $key_16fd = { 42 95 [2] 36 8d [2] 71 8f [2] 36 9e [2] 78 92 [2] 74 98 [2] 63 93 [2] 78 dd [2] 45 }

  condition:
    any of them
}