rule TTP_XOR_MULT_DOSStub_b2fd {
  strings:
    $key_b2fd = { e6 95 [2] 92 8d [2] d5 8f [2] 92 9e [2] dc 92 [2] d0 98 [2] c7 93 [2] dc dd [2] e1 }

  condition:
    any of them
}