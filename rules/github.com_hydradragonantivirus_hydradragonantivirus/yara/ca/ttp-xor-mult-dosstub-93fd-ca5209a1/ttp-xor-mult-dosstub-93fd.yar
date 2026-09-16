rule TTP_XOR_MULT_DOSStub_93fd {
  strings:
    $key_93fd = { c7 95 [2] b3 8d [2] f4 8f [2] b3 9e [2] fd 92 [2] f1 98 [2] e6 93 [2] fd dd [2] c0 }

  condition:
    any of them
}