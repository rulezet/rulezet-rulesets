rule TTP_XOR_MULT_DOSStub_c2fa {
  strings:
    $key_c2fa = { 96 92 [2] e2 8a [2] a5 88 [2] e2 99 [2] ac 95 [2] a0 9f [2] b7 94 [2] ac da [2] 91 }

  condition:
    any of them
}