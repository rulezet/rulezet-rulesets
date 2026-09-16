rule TTP_XOR_MULT_DOSStub_84fd {
  strings:
    $key_84fd = { d0 95 [2] a4 8d [2] e3 8f [2] a4 9e [2] ea 92 [2] e6 98 [2] f1 93 [2] ea dd [2] d7 }

  condition:
    any of them
}