rule TTP_XOR_MULT_DOSStub_c7ff {
  strings:
    $key_c7ff = { 93 97 [2] e7 8f [2] a0 8d [2] e7 9c [2] a9 90 [2] a5 9a [2] b2 91 [2] a9 df [2] 94 }

  condition:
    any of them
}