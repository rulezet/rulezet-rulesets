rule TTP_XOR_MULT_DOSStub_31fd {
  strings:
    $key_31fd = { 65 95 [2] 11 8d [2] 56 8f [2] 11 9e [2] 5f 92 [2] 53 98 [2] 44 93 [2] 5f dd [2] 62 }

  condition:
    any of them
}