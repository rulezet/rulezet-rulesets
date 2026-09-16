rule TTP_XOR_MULT_DOSStub_26fc {
  strings:
    $key_26fc = { 72 94 [2] 06 8c [2] 41 8e [2] 06 9f [2] 48 93 [2] 44 99 [2] 53 92 [2] 48 dc [2] 75 }

  condition:
    any of them
}