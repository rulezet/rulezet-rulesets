rule TTP_XOR_MULT_DOSStub_c6ff {
  strings:
    $key_c6ff = { 92 97 [2] e6 8f [2] a1 8d [2] e6 9c [2] a8 90 [2] a4 9a [2] b3 91 [2] a8 df [2] 95 }

  condition:
    any of them
}