rule TTP_XOR_MULT_DOSStub_22fd {
  strings:
    $key_22fd = { 76 95 [2] 02 8d [2] 45 8f [2] 02 9e [2] 4c 92 [2] 40 98 [2] 57 93 [2] 4c dd [2] 71 }

  condition:
    any of them
}